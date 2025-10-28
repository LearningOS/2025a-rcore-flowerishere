//! Task management implementation
//!
//! Everything about task management, like starting and switching tasks is
//! implemented here.
//!
//! A single global instance of [`TaskManager`] called `TASK_MANAGER` controls
//! all the tasks in the operating system.

mod context;
mod switch;
#[allow(clippy::module_inception)]
mod task;
use crate::config::{MAX_SYSCALL_NUM, MAX_APP_NUM};
use crate::loader::{get_app_data, get_num_app};
use crate::sync::UPSafeCell;
use crate::trap::TrapContext;
use crate::mm::{VirtAddr, VirtPageNum, MapPermission, VPNRange};
use alloc::vec::Vec;
use lazy_static::*;
use switch::__switch;
pub use task::{TaskControlBlock, TaskStatus};

pub use context::TaskContext;

/// Task information structure for system call 
#[derive(Copy, Clone)]
pub struct TaskInfo {
    /// Array storing the count of each system call made by the task
    pub syscall_count: [usize; MAX_SYSCALL_NUM],
    /// Current status of the task
    pub status: TaskStatus,
    /// Time information for the task
    pub time: usize,
}

impl Default for TaskInfo {
    fn default() -> Self {
        Self {
            status: TaskStatus::UnInit,
            syscall_count: [0; MAX_SYSCALL_NUM],
            time: 0,
        }
    }
}

/// The task manager, where all the tasks are managed.
pub struct TaskManager {
    /// total number of tasks
    num_app: usize,
    /// use inner value to get mutable access
    inner: UPSafeCell<TaskManagerInner>,
}

/// The task manager inner in 'UPSafeCell'
struct TaskManagerInner {
    /// task list
    tasks: Vec<Option<TaskControlBlock>>,
    /// id of current `Running` task
    current_task: usize,
    /// syscall count of task
    task_info_map: [TaskInfo; MAX_APP_NUM],
}

lazy_static! {
    /// a `TaskManager` global instance through lazy_static!
    pub static ref TASK_MANAGER: TaskManager = {
        println!("init TASK_MANAGER");
        let num_app = get_num_app();
        println!("num_app = {}", num_app);
        
        let mut tasks = Vec::new();
        for i in 0..MAX_APP_NUM {
            if i < num_app {
                tasks.push(Some(TaskControlBlock::new(get_app_data(i), i)));
            } else {
                tasks.push(None);
            }
        }

        let mut task_info_map = [TaskInfo::default(); MAX_APP_NUM];
        for i in 0..num_app {
            task_info_map[i] = TaskInfo {
                status: TaskStatus::Ready,
                syscall_count: [0; MAX_SYSCALL_NUM],
                time: 0,
            };
        }
        
        TaskManager {
            num_app,
            inner: unsafe {
                UPSafeCell::new(TaskManagerInner {
                    tasks,
                    current_task: 0,
                    task_info_map,
                })
            },
        }
    };
}

impl TaskManager {
    /// Run the first task in task list.
    fn run_first_task(&self) -> ! {
        let mut inner = self.inner.exclusive_access();
        if let Some(ref mut next_task) = inner.tasks[0] {
            next_task.task_status = TaskStatus::Running;
            let next_task_cx_ptr = &next_task.task_cx as *const TaskContext;
            drop(inner);
            let mut _unused = TaskContext::zero_init();
            unsafe {
                __switch(&mut _unused as *mut _, next_task_cx_ptr);
            }
        }
        panic!("unreachable in run_first_task!");
    }

    /// Change the status of current `Running` task into `Ready`.
    fn mark_current_suspended(&self) {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;
        if let Some(ref mut task) = inner.tasks[cur] {
            task.task_status = TaskStatus::Ready;
        }
    }

    /// Change the status of current `Running` task into `Exited`.
    fn mark_current_exited(&self) {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;
        if let Some(ref mut task) = inner.tasks[cur] {
            task.task_status = TaskStatus::Exited;
        }
    }

    /// Find next task to run and return task id.
    fn find_next_task(&self) -> Option<usize> {
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        (current + 1..current + self.num_app + 1)
            .map(|id| id % self.num_app)
            .find(|&id| {
                if let Some(ref task) = inner.tasks[id] {
                    task.task_status == TaskStatus::Ready
                } else {
                    false
                }
            })
    }

    /// Get the current 'Running' task's token.
    fn get_current_token(&self) -> usize {
        let inner = self.inner.exclusive_access();
        if let Some(ref task) = inner.tasks[inner.current_task] {
            task.get_user_token()
        } else {
            0
        }
    }

    /// Get the current 'Running' task's trap contexts.
    fn get_current_trap_cx(&self) -> &'static mut TrapContext {
        let inner = self.inner.exclusive_access();
        if let Some(ref task) = inner.tasks[inner.current_task] {
            task.get_trap_cx()
        } else {
            panic!("No current task");
        }
    }

    /// Change the current 'Running' task's program break
    pub fn change_current_program_brk(&self, size: i32) -> Option<usize> {
        let mut inner = self.inner.exclusive_access();
        let cur = inner.current_task;
        if let Some(ref mut task) = inner.tasks[cur] {
            task.change_program_brk(size)
        } else {
            None
        }
    }

    /// Switch current `Running` task to the task we have found
    fn run_next_task(&self) {
        if let Some(next) = self.find_next_task() {
            let mut inner = self.inner.exclusive_access();
            let current = inner.current_task;
            
            if let Some(ref mut next_task) = inner.tasks[next] {
                next_task.task_status = TaskStatus::Running;
            }
            inner.current_task = next;
            
            let current_task_cx_ptr = if let Some(ref mut current_task) = inner.tasks[current] {
                &mut current_task.task_cx as *mut TaskContext
            } else {
                panic!("No current task");
            };
            
            let next_task_cx_ptr = if let Some(ref next_task) = inner.tasks[next] {
                &next_task.task_cx as *const TaskContext
            } else {
                panic!("No next task");
            };
            
            drop(inner);
            unsafe {
                __switch(current_task_cx_ptr, next_task_cx_ptr);
            }
        } else {
            panic!("All applications completed!");
        }
    }

    /// Increment syscall count
    pub fn inc_current_syscall_count(&self, syscall_id: usize) {
        let mut inner = self.inner.exclusive_access();
        let current = inner.current_task;
        if syscall_id < MAX_SYSCALL_NUM {
            inner.task_info_map[current].syscall_count[syscall_id] += 1;
        }
    }

    /// Get syscall count
    pub fn get_current_syscall_count(&self, syscall_id: usize) -> usize {
        let inner = self.inner.exclusive_access();
        let current = inner.current_task;
        if syscall_id < MAX_SYSCALL_NUM {
            inner.task_info_map[current].syscall_count[syscall_id]
        } else {
            0
        }
    }

    /// Task mmap implementation
    pub fn task_mmap(&self, start_va: VirtAddr, end_va: VirtAddr, start_vpn: VirtPageNum, end_vpn: VirtPageNum, map_perm: MapPermission) -> bool {
        let mut inner = self.inner.exclusive_access();
        let current_task = inner.current_task;
        if let Some(ref mut task) = inner.tasks[current_task] {
            for vpn in VPNRange::new(start_vpn, end_vpn) {
                if let Some(pte) = task.memory_set.translate(vpn) {
                    if pte.is_valid() {
                        return false;
                    }
                }
            }
            task.memory_set.insert_framed_area(start_va, end_va, map_perm);
            true
        } else {
            false
        }
    }

    /// Task munmap implementation
    pub fn task_munmap(&self, start_vpn: VirtPageNum, end_vpn: VirtPageNum) -> bool {
        let mut inner = self.inner.exclusive_access();
        let current_task = inner.current_task;
        if let Some(ref mut task) = inner.tasks[current_task] {
            for vpn in VPNRange::new(start_vpn, end_vpn) {
                if let Some(pte) = task.memory_set.translate(vpn) {
                    if !pte.is_valid() {
                        return false;
                    }
                } else {
                    return false;
                }
                task.memory_set.unmap(vpn);
            }
            true
        } else {
            false
        }
    }
}

/// Run the first task in task list.
pub fn run_first_task() {
    TASK_MANAGER.run_first_task();
}

/// Switch current `Running` task to the next task
fn run_next_task() {
    TASK_MANAGER.run_next_task();
}

/// Change the status of current `Running` task into `Ready`.
fn mark_current_suspended() {
    TASK_MANAGER.mark_current_suspended();
}

/// Change the status of current `Running` task into `Exited`.
fn mark_current_exited() {
    TASK_MANAGER.mark_current_exited();
}

/// Suspend the current 'Running' task and run the next task
pub fn suspend_current_and_run_next() {
    mark_current_suspended();
    run_next_task();
}

/// Exit the current 'Running' task and run the next task
pub fn exit_current_and_run_next() {
    mark_current_exited();
    run_next_task();
}

/// Get the current 'Running' task's token.
pub fn current_user_token() -> usize {
    TASK_MANAGER.get_current_token()
}

/// Get the current 'Running' task's trap contexts.
pub fn current_trap_cx() -> &'static mut TrapContext {
    TASK_MANAGER.get_current_trap_cx()
}

/// Change the current 'Running' task's program break
pub fn change_program_brk(size: i32) -> Option<usize> {
    TASK_MANAGER.change_current_program_brk(size)
}