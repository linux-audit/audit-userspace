/* x86_64_table.h --
 * Copyright 2005-24 Red Hat Inc.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *      Steve Grubb <sgrubb@redhat.com>
 */

_S(0, "read")
_S(1, "write")
_S(2, "open")
_S(3, "close")
_S(4, "stat")
_S(5, "fstat")
_S(6, "lstat")
_S(7, "poll")
_S(8, "lseek")
_S(9, "mmap")
_S(10, "mprotect")
_S(11, "munmap")
_S(12, "brk")
_S(13, "rt_sigaction")
_S(14, "rt_sigprocmask")
_S(15, "rt_sigreturn")
_S(16, "ioctl")
_S(17, "pread")
_S(18, "pwrite")
_S(19, "readv")
_S(20, "writev")
_S(21, "access")
_S(22, "pipe")
_S(23, "select")
_S(24, "sched_yield")
_S(25, "mremap")
_S(26, "msync")
_S(27, "mincore")
_S(28, "madvise")
_S(29, "shmget")
_S(30, "shmat")
_S(31, "shmctl")
_S(32, "dup")
_S(33, "dup2")
_S(34, "pause")
_S(35, "nanosleep")
_S(36, "getitimer")
_S(37, "alarm")
_S(38, "setitimer")
_S(39, "getpid")
_S(40, "sendfile")
_S(41, "socket")
_S(42, "connect")
_S(43, "accept")
_S(44, "sendto")
_S(45, "recvfrom")
_S(46, "sendmsg")
_S(47, "recvmsg")
_S(48, "shutdown")
_S(49, "bind")
_S(50, "listen")
_S(51, "getsockname")
_S(52, "getpeername")
_S(53, "socketpair")
_S(54, "setsockopt")
_S(55, "getsockopt")
_S(56, "clone")
_S(57, "fork")
_S(58, "vfork")
_S(59, "execve")
_S(60, "exit")
_S(61, "wait4")
_S(62, "kill")
_S(63, "uname")
_S(64, "semget")
_S(65, "semop")
_S(66, "semctl")
_S(67, "shmdt")
_S(68, "msgget")
_S(69, "msgsnd")
_S(70, "msgrcv")
_S(71, "msgctl")
_S(72, "fcntl")
_S(73, "flock")
_S(74, "fsync")
_S(75, "fdatasync")
_S(76, "truncate")
_S(77, "ftruncate")
_S(78, "getdents")
_S(79, "getcwd")
_S(80, "chdir")
_S(81, "fchdir")
_S(82, "rename")
_S(83, "mkdir")
_S(84, "rmdir")
_S(85, "creat")
_S(86, "link")
_S(87, "unlink")
_S(88, "symlink")
_S(89, "readlink")
_S(90, "chmod")
_S(91, "fchmod")
_S(92, "chown")
_S(93, "fchown")
_S(94, "lchown")
_S(95, "umask")
_S(96, "gettimeofday")
_S(97, "getrlimit")
_S(98, "getrusage")
_S(99, "sysinfo")
_S(100, "times")
_S(101, "ptrace")
_S(102, "getuid")
_S(103, "syslog")
_S(104, "getgid")
_S(105, "setuid")
_S(106, "setgid")
_S(107, "geteuid")
_S(108, "getegid")
_S(109, "setpgid")
_S(110, "getppid")
_S(111, "getpgrp")
_S(112, "setsid")
_S(113, "setreuid")
_S(114, "setregid")
_S(115, "getgroups")
_S(116, "setgroups")
_S(117, "setresuid")
_S(118, "getresuid")
_S(119, "setresgid")
_S(120, "getresgid")
_S(121, "getpgid")
_S(122, "setfsuid")
_S(123, "setfsgid")
_S(124, "getsid")
_S(125, "capget")
_S(126, "capset")
_S(127, "rt_sigpending")
_S(128, "rt_sigtimedwait")
_S(129, "rt_sigqueueinfo")
_S(130, "rt_sigsuspend")
_S(131, "sigaltstack")
_S(132, "utime")
_S(133, "mknod")
_S(134, "uselib")
_S(135, "personality")
_S(136, "ustat")
_S(137, "statfs")
_S(138, "fstatfs")
_S(139, "sysfs")
_S(140, "getpriority")
_S(141, "setpriority")
_S(142, "sched_setparam")
_S(143, "sched_getparam")
_S(144, "sched_setscheduler")
_S(145, "sched_getscheduler")
_S(146, "sched_get_priority_max")
_S(147, "sched_get_priority_min")
_S(148, "sched_rr_get_interval")
_S(149, "mlock")
_S(150, "munlock")
_S(151, "mlockall")
_S(152, "munlockall")
_S(153, "vhangup")
_S(154, "modify_ldt")
_S(155, "pivot_root")
_S(156, "_sysctl")
_S(157, "prctl")
_S(158, "arch_prctl")
_S(159, "adjtimex")
_S(160, "setrlimit")
_S(161, "chroot")
_S(162, "sync")
_S(163, "acct")
_S(164, "settimeofday")
_S(165, "mount")
_S(166, "umount2")
_S(167, "swapon")
_S(168, "swapoff")
_S(169, "reboot")
_S(170, "sethostname")
_S(171, "setdomainname")
_S(172, "iopl")
_S(173, "ioperm")
_S(174, "create_module")
_S(175, "init_module")
_S(176, "delete_module")
_S(177, "get_kernel_syms")
_S(178, "query_module")
_S(179, "quotactl")
_S(180, "nfsservctl")
_S(181, "getpmsg")
_S(182, "putpmsg")
_S(183, "afs_syscall")
_S(184, "tuxcall")
_S(185, "security")
_S(186, "gettid")
_S(187, "readahead")
_S(188, "setxattr")
_S(189, "lsetxattr")
_S(190, "fsetxattr")
_S(191, "getxattr")
_S(192, "lgetxattr")
_S(193, "fgetxattr")
_S(194, "listxattr")
_S(195, "llistxattr")
_S(196, "flistxattr")
_S(197, "removexattr")
_S(198, "lremovexattr")
_S(199, "fremovexattr")
_S(200, "tkill")
_S(201, "time")
_S(202, "futex")
_S(203, "sched_setaffinity")
_S(204, "sched_getaffinity")
_S(205, "set_thread_area")
_S(206, "io_setup")
_S(207, "io_destroy")
_S(208, "io_getevents")
_S(209, "io_submit")
_S(210, "io_cancel")
_S(211, "get_thread_area")
_S(212, "lookup_dcookie")
_S(213, "epoll_create")
_S(214, "epoll_ctl_old")
_S(215, "epoll_wait_old")
_S(216, "remap_file_pages")
_S(217, "getdents64")
_S(218, "set_tid_address")
_S(219, "restart_syscall")
_S(220, "semtimedop")
_S(221, "fadvise64")
_S(222, "timer_create")
_S(223, "timer_settime")
_S(224, "timer_gettime")
_S(225, "timer_getoverrun")
_S(226, "timer_delete")
_S(227, "clock_settime")
_S(228, "clock_gettime")
_S(229, "clock_getres")
_S(230, "clock_nanosleep")
_S(231, "exit_group")
_S(232, "epoll_wait")
_S(233, "epoll_ctl")
_S(234, "tgkill")
_S(235, "utimes")
_S(236, "vserver")
_S(237, "mbind")
_S(238, "set_mempolicy")
_S(239, "get_mempolicy")
_S(240, "mq_open")
_S(241, "mq_unlink")
_S(242, "mq_timedsend")
_S(243, "mq_timedreceive")
_S(244, "mq_notify")
_S(245, "mq_getsetattr")
_S(246, "kexec_load")
_S(247, "waitid")
_S(248, "add_key")
_S(249, "request_key")
_S(250, "keyctl")
_S(251, "ioprio_set")
_S(252, "ioprio_get")
_S(253, "inotify_init")
_S(254, "inotify_add_watch")
_S(255, "inotify_rm_watch")
_S(256, "migrate_pages")
_S(257, "openat")
_S(258, "mkdirat")
_S(259, "mknodat")
_S(260, "fchownat")
_S(261, "futimesat")
_S(262, "newfstatat")
_S(263, "unlinkat")
_S(264, "renameat")
_S(265, "linkat")
_S(266, "symlinkat")
_S(267, "readlinkat")
_S(268, "fchmodat")
_S(269, "faccessat")
_S(270, "pselect6")
_S(271, "ppoll")
_S(272, "unshare")
_S(273, "set_robust_list")
_S(274, "get_robust_list")
_S(275, "splice")
_S(276, "tee")
_S(277, "sync_file_range")
_S(278, "vmsplice")
_S(279, "move_pages")
_S(280, "utimensat")
_S(281, "epoll_pwait")
_S(282, "signalfd")
_S(283, "timerfd_create")
_S(284, "eventfd")
_S(285, "fallocate")
_S(286, "timerfd_settime")
_S(287, "timerfd_gettime")
_S(288, "accept4")
_S(289, "signalfd4")
_S(290, "eventfd2")
_S(291, "epoll_create1")
_S(292, "dup3")
_S(293, "pipe2")
_S(294, "inotify_init1")
_S(295, "preadv")
_S(296, "pwritev")
_S(297, "rt_tgsigqueueinfo")
_S(298, "perf_event_open")
_S(299, "recvmmsg")
_S(300, "fanotify_init")
_S(301, "fanotify_mark")
_S(302, "prlimit64")
_S(303, "name_to_handle_at")
_S(304, "open_by_handle_at")
_S(305, "clock_adjtime")
_S(306, "syncfs")
_S(307, "sendmmsg")
_S(308, "setns")
_S(309, "getcpu")
_S(310, "process_vm_readv")
_S(311, "process_vm_writev")
_S(312, "kcmp")
_S(313, "finit_module")
_S(314, "sched_setattr")
_S(315, "sched_getattr")
_S(316, "renameat2")
_S(317, "seccomp")
_S(318, "getrandom")
_S(319, "memfd_create")
_S(320, "kexec_file_load")
_S(321, "bpf")
_S(322, "execveat")
_S(323, "userfaultfd")
_S(324, "membarrier")
_S(325, "mlock2")
_S(326, "copy_file_range")
_S(327, "preadv2")
_S(328, "pwritev2")
_S(329, "pkey_mprotect")
_S(330, "pkey_alloc")
_S(331, "pkey_free")
_S(332, "statx")
_S(333, "io_pgetevents")
_S(334, "rseq")
_S(424, "pidfd_send_signal")
_S(425, "io_uring_setup")
_S(426, "io_uring_enter")
_S(427, "io_uring_register")
_S(428, "open_tree")
_S(429, "move_mount")
_S(430, "fsopen")
_S(431, "fsconfig")
_S(432, "fsmount")
_S(433, "fspick")
_S(434, "pidfd_open")
_S(435, "clone3")
_S(436, "close_range")
_S(437, "openat2")
_S(438, "pidfd_getfd")
_S(439, "faccessat2")
_S(440, "process_madvise")
_S(441, "epoll_pwait2")
_S(442, "mount_setattr")
_S(443, "quotactl_fd")
_S(444, "landlock_create_ruleset")
_S(445, "landlock_add_rule")
_S(446, "landlock_restrict_self")
_S(447, "memfd_secret")
_S(448, "process_mrelease")
_S(449, "futex_waitv")
_S(450, "set_mempolicy_home_node")
_S(451, "cachestat")
_S(452, "fchmodat2")
_S(453, "map_shadow_stack")
_S(454, "futex_wake")
_S(455, "futex_wait")
_S(456, "futex_requeue")
_S(457, "statmount")
_S(458, "listmount")
_S(459, "lsm_get_self_attr")
_S(460, "lsm_set_self_attr")
_S(461, "lsm_list_modules")
_S(462, "mseal")
_S(463, "setxattrat")
_S(464, "getxattrat")
_S(465, "listxattrat")
_S(466, "removexattrat")
