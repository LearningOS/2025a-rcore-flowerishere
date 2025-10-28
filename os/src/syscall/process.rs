//! Process management syscalls
use crate::task::{change_program_brk, exit_current_and_run_next, suspend_current_and_run_next, current_user_token, TASK_MANAGER};
use crate::mm::{VirtAddr, MapPermission, read_one_bytes, write_one_bytes, translated_refmut};
use crate::config::PAGE_SIZE;
use crate::timer::get_time_us;

#[repr(C)]
#[derive(Debug)]
pub struct TimeVal {
    pub sec: usize,
    pub usec: usize,
}

/// task exits and submit an exit code
pub fn sys_exit(_exit_code: i32) -> ! {
    trace!("kernel: sys_exit");
    exit_current_and_run_next();
    panic!("Unreachable in sys_exit!");
}

/// current task gives up resources for other tasks
pub fn sys_yield() -> isize {
    trace!("kernel: sys_yield");
    suspend_current_and_run_next();
    0
}

/// Get time with second and microsecond
pub fn sys_get_time(ts: *mut TimeVal, _tz: usize) -> isize {
    let us = get_time_us();
    let token = current_user_token();
    
    let ts_ref = translated_refmut(token, ts);
    ts_ref.sec = us / 1_000_000;
    ts_ref.usec = us % 1_000_000;
    0
}

/// Trace syscall for debugging and monitoring
pub fn sys_trace(trace_request: usize, id: usize, data: usize) -> isize {
    trace!("kernel: sys_trace");
    
    match trace_request {
        0 => {
            // Read one byte from address
            if let Some(byte) = read_one_bytes(current_user_token(), id as *const u8) {
                trace!("kernel: read data {:x} from addr {:x}", byte, id);
                byte as isize
            } else {
                -1
            }
        }
        1 => {
            // Write one byte to address
            if write_one_bytes(current_user_token(), id as *mut u8, data as u8) {
                trace!("kernel: write data {:x} to addr {:x}", data, id);
                0
            } else {
                -1
            }
        }
        2 => {
            // Get syscall count
            TASK_MANAGER.get_current_syscall_count(id) as isize
        }
        _ => -1,
    }
}

/// Memory map syscall
pub fn sys_mmap(start: usize, len: usize, port: usize) -> isize {
    trace!("kernel: sys_mmap start={:#x}, len={:#x}, port={:#x}", start, len, port);
    if start % PAGE_SIZE != 0 {
        return -1;
    }
    if port & !0x7 != 0 || port & 0x7 == 0 {
        return -1;
    }
    if len == 0 {
        return 0;
    }

    let mut map_perm = MapPermission::U;

    if port & 0x1 != 0 {
        map_perm |= MapPermission::R;
    }
    if port & 0x2 != 0 {
        map_perm |= MapPermission::W;
    }
    if port & 0x4 != 0 {
        map_perm |= MapPermission::X;
    }
    let start_va: VirtAddr = VirtAddr::from(start);
    let end_va: VirtAddr = VirtAddr::from(start + len);
    let start_vpn = start_va.floor();
    let end_vpn = end_va.ceil();
    let pass = TASK_MANAGER.task_mmap(start_va, end_va, start_vpn, end_vpn, map_perm);
    if pass {
        0
    } else {
        -1
    }
}

/// Memory unmap syscall
pub fn sys_munmap(start: usize, len: usize) -> isize {
    trace!("kernel: sys_munmap start={:#x}, len={:#x}", start, len);
    if start % PAGE_SIZE != 0 {
        return -1;
    }
    if len == 0 {
        return 0;
    }

    let start_va: VirtAddr = VirtAddr::from(start);
    let end_va: VirtAddr = VirtAddr::from(start + len);
    let start_vpn = start_va.floor();
    let end_vpn = end_va.ceil();
    let pass = TASK_MANAGER.task_munmap(start_vpn, end_vpn);
    if pass {
        0
    } else {
        -1
    }
}

/// Change data segment size
pub fn sys_sbrk(size: i32) -> isize {
    trace!("kernel: sys_sbrk");
    if let Some(old_brk) = change_program_brk(size) {
        old_brk as isize
    } else {
        -1
    }
}