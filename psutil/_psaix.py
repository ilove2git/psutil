#!/usr/bin/env python

# Copyright (c) 2009, Giampaolo Rodola'. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""AIX platform implementation."""

import errno
import glob
import os
import re
import subprocess
import sys
from collections import namedtuple

from . import _common
from . import _psposix
from . import _psutil_posix as cext_posix
from . import _psutil_aix as cext
from ._common import socktype_to_enum, sockfam_to_enum
from ._common import NIC_DUPLEX_FULL, NIC_DUPLEX_HALF, NIC_DUPLEX_UNKNOWN
from ._common import usage_percent
from ._compat import PY3


__extra__all__ = []


PAGE_SIZE = os.sysconf('SC_PAGE_SIZE')
AF_LINK = cext_posix.AF_LINK

PROC_STATUSES = {

    cext.SIDL: _common.STATUS_IDLE,
    cext.SRUN: _common.STATUS_RUNNING,
    cext.SSLEEP: _common.STATUS_SLEEPING,
    cext.SSWAP: _common.STATUS_RUNNING,      # TODO what status is this?
    cext.SSTOP: _common.STATUS_STOPPED,
    cext.SZOMB: _common.STATUS_ZOMBIE
}

TCP_STATUSES = {
    cext.TCPS_ESTABLISHED: _common.CONN_ESTABLISHED,
    cext.TCPS_SYN_SENT: _common.CONN_SYN_SENT,
    cext.TCPS_SYN_RCVD: _common.CONN_SYN_RECV,
    cext.TCPS_FIN_WAIT_1: _common.CONN_FIN_WAIT1,
    cext.TCPS_FIN_WAIT_2: _common.CONN_FIN_WAIT2,
    cext.TCPS_TIME_WAIT: _common.CONN_TIME_WAIT,
    cext.TCPS_CLOSED: _common.CONN_CLOSE,
    cext.TCPS_CLOSE_WAIT: _common.CONN_CLOSE_WAIT,
    cext.TCPS_LAST_ACK: _common.CONN_LAST_ACK,
    cext.TCPS_LISTEN: _common.CONN_LISTEN,
    cext.TCPS_CLOSING: _common.CONN_CLOSING,
    cext.PSUTIL_CONN_NONE: _common.CONN_NONE,
}

scputimes = namedtuple('scputimes', ['user', 'system', 'idle', 'iowait'])
svmem = namedtuple('svmem', ['total', 'available', 'percent', 'used', 'free'])
pmmap_grouped = namedtuple('pmmap_grouped', ['path', 'rss', 'anon', 'locked'])
pmmap_ext = namedtuple(
    'pmmap_ext', 'addr perms ' + ' '.join(pmmap_grouped._fields))

# set later from __init__.py
NoSuchProcess = None
ZombieProcess = None
AccessDenied = None
TimeoutExpired = None

# --- functions

disk_io_counters = cext.disk_io_counters
disk_usage = _psposix.disk_usage
net_if_addrs = cext_posix.net_if_addrs
net_io_counters = cext.net_io_counters


def virtual_memory():
    total, free, pinned, inuse = cext.virtual_mem()
    total = total * PAGE_SIZE
    avail = free * PAGE_SIZE
    used = inuse * PAGE_SIZE
    percent = usage_percent((total - avail), total, _round=1)
    return svmem(total, avail, percent, used, free)


def pids():
    """Returns a list of PIDs currently running on the system."""
    return [int(x) for x in os.listdir('/proc') if x.isdigit()]


def pid_exists(pid):
    """Check for the existence of a unix pid."""
    return _psposix.pid_exists(pid)


def swap_memory():
    """Swap system memory as a (total, used, free, sin, sout) tuple."""
    total, free, sin, sout = cext.swap_mem()
    used = total - free
    percent = usage_percent(used, total, _round=1)
    return _common.sswap(total, used, free, percent, sin, sout)


def cpu_times():
    """Return system-wide CPU times as a named tuple"""
    ret = cext.per_cpu_times()
    return scputimes(*[sum(x) for x in zip(*ret)])


def per_cpu_times():
    """Return system per-CPU times as a list of named tuples"""
    ret = cext.per_cpu_times()
    return [scputimes(*x) for x in ret]


def cpu_count_logical():
    """Return the number of logical CPUs in the system."""
    try:
        return os.sysconf("SC_NPROCESSORS_ONLN")
    except ValueError:
        # mimic os.cpu_count() behavior
        return None


def cpu_count_physical():
    cmd = "lsdev -Cc processor"
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    if PY3:
        stdout, stderr = [x.decode(sys.stdout.encoding)
                          for x in (stdout, stderr)]
    if p.returncode != 0:
        raise RuntimeError("%r command error\n%s" % (cmd, stderr))
    processors = stdout.strip().splitlines()
    return len(processors)


def boot_time():
    """The system boot time expressed in seconds since the epoch."""
    return cext.boot_time()


def users():
    """Return currently connected users as a list of namedtuples."""
    retlist = []
    rawlist = cext.users()
    localhost = (':0.0', ':0')
    for item in rawlist:
        user, tty, hostname, tstamp, user_process = item
        # note: the underlying C function includes entries about
        # system boot, run level and others.  We might want
        # to use them in the future.
        if not user_process:
            continue
        if hostname in localhost:
            hostname = 'localhost'
        nt = _common.suser(user, tty, hostname, tstamp)
        retlist.append(nt)
    return retlist


def disk_partitions(all=False):
    """Return system disk partitions."""
    # TODO - the filtering logic should be better checked so that
    # it tries to reflect 'df' as much as possible
    retlist = []
    partitions = cext.disk_partitions()
    for partition in partitions:
        device, mountpoint, fstype, opts = partition
        if device == 'none':
            device = ''
        if not all:
            # Differently from, say, Linux, we don't have a list of
            # common fs types so the best we can do, AFAIK, is to
            # filter by filesystem having a total size > 0.
            if not disk_usage(mountpoint).total:
                continue
        ntuple = _common.sdiskpart(device, mountpoint, fstype, opts)
        retlist.append(ntuple)
    return retlist


def net_connections(kind, _pid=-1):
    """Return socket connections.  If pid == -1 return system-wide
    connections (as opposed to connections opened by one process only).
    """
    cmap = _common.conn_tmap.copy()
    if kind not in cmap:
        raise ValueError("invalid %r kind argument; choose between %s"
                         % (kind, ', '.join([repr(x) for x in cmap])))
    families, types = _common.conn_tmap[kind]
    rawlist = cext.net_connections(_pid)
    ret = set()
    for item in rawlist:
        fd, fam, type_, laddr, raddr, status, pid = item
        if fam not in families:
            continue
        if type_ not in types:
            continue
        status = TCP_STATUSES[status]
        fam = sockfam_to_enum(fam)
        type_ = socktype_to_enum(type_)
        if _pid == -1:
            nt = _common.sconn(fd, fam, type_, laddr, raddr, status, pid)
        else:
            nt = _common.pconn(fd, fam, type_, laddr, raddr, status)
        ret.add(nt)
    return list(ret)


def net_if_stats():
    """Get NIC stats (isup, duplex, speed, mtu)."""
    duplex_map = {"Full": NIC_DUPLEX_FULL,
                  "Half": NIC_DUPLEX_HALF}
    names = set([x[0] for x in net_if_addrs()])
    ret = {}
    for name in names:
        isup, mtu = cext.net_if_stats(name)

        # try to get speed and duplex
        duplex = ""
        speed = 0
        p = subprocess.Popen(["/usr/bin/entstat", "-d", name],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        if PY3:
            stdout, stderr = [x.decode(sys.stdout.encoding)
                              for x in (stdout, stderr)]
        if p.returncode == 0:
            re_result = re.search("Running: (\d+) Mbps.*?(\w+) Duplex", stdout)
            if re_result is not None:
                speed = int(re_result.group(1))
                duplex = re_result.group(2)

        duplex = duplex_map.get(duplex, NIC_DUPLEX_UNKNOWN)
        ret[name] = _common.snicstats(isup, duplex, speed, mtu)
    return ret


def wrap_exceptions(fun):
    """Call callable into a try/except clause and translate ENOENT,
    EACCES and EPERM in NoSuchProcess or AccessDenied exceptions.
    """
    def wrapper(self, *args, **kwargs):
        try:
            return fun(self, *args, **kwargs)
        except EnvironmentError as err:
            # support for private module import
            if (NoSuchProcess is None or AccessDenied is None or
                    ZombieProcess is None):
                raise
            # ENOENT (no such file or directory) gets raised on open().
            # ESRCH (no such process) can get raised on read() if
            # process is gone in meantime.
            if err.errno in (errno.ENOENT, errno.ESRCH):
                if not pid_exists(self.pid):
                    raise NoSuchProcess(self.pid, self._name)
                else:
                    raise ZombieProcess(self.pid, self._name, self._ppid)
            if err.errno in (errno.EPERM, errno.EACCES):
                raise AccessDenied(self.pid, self._name)
            raise
    return wrapper


class Process(object):
    """Wrapper class around underlying C implementation."""

    __slots__ = ["pid", "_name", "_ppid"]

    def __init__(self, pid):
        self.pid = pid
        self._name = None
        self._ppid = None

    @wrap_exceptions
    def name(self):
        # note: this is limited to 15 characters
        return cext.proc_name_and_args(self.pid)[0].rstrip("\x00")

    @wrap_exceptions
    def exe(self):
        # there is no way to get executable path in AIX other than to guess,
        # and guessing is more complex than what's in the wrapping class
        exe = self.cmdline()[0]
        if os.path.sep in exe:
            # relative or absolute path
            if not os.path.isabs(exe):
                # if cwd has changed, we're out of luck - this may be wrong!
                exe = os.path.abspath(os.path.join(self.cwd(), exe))
            if (os.path.isabs(exe) and
               os.path.isfile(exe) and
               os.access(exe, os.X_OK)):
                return exe
            # not found, move to search in PATH using basename only
            exe = os.path.basename(exe)
        # search for exe name PATH
        for path in os.environ["PATH"].split(":"):
            possible_exe = os.path.abspath(os.path.join(path, exe))
            if (os.path.isfile(possible_exe) and
               os.access(possible_exe, os.X_OK)):
                return possible_exe
        return ''

    @wrap_exceptions
    def cmdline(self):
        return cext.proc_name_and_args(self.pid)[1].split(' ')

    @wrap_exceptions
    def create_time(self):
        return cext.proc_basic_info(self.pid)[3]

    @wrap_exceptions
    def num_threads(self):
        return cext.proc_basic_info(self.pid)[5]

    @wrap_exceptions
    def threads(self):
        rawlist = cext.proc_threads(self.pid)
        retlist = []
        for thread_id, utime, stime in rawlist:
            ntuple = _common.pthread(thread_id, utime, stime)
            retlist.append(ntuple)
        # The underlying C implementation retrieves all OS threads
        # and filters them by PID.  At this point we can't tell whether
        # an empty list means there were no connections for process or
        # process is no longer active so we force NSP in case the PID
        # is no longer there.
        if not retlist:
            os.stat('/proc/%s' % self.pid)  # will raise NSP if process is gone
        return retlist

    @wrap_exceptions
    def connections(self, kind='inet'):
        ret = net_connections(kind, _pid=self.pid)
        # The underlying C implementation retrieves all OS connections
        # and filters them by PID.  At this point we can't tell whether
        # an empty list means there were no connections for process or
        # process is no longer active so we force NSP in case the PID
        # is no longer there.
        if not ret:
            os.stat('/proc/%s' % self.pid)  # will raise NSP if process is gone
        return ret

    @wrap_exceptions
    def nice_get(self):
        # For some reason getpriority(3) return ESRCH (no such process)
        # for certain low-pid processes, no matter what (even as root).
        # The process actually exists though, as it has a name,
        # creation time, etc.
        # The best thing we can do here appears to be raising AD.
        # Note: tested on Solaris 11; on Open Solaris 5 everything is
        # fine.
        try:
            return cext_posix.getpriority(self.pid)
        except EnvironmentError as err:
            # 48 is 'operation not supported' but errno does not expose
            # it. It occurs for low system pids.
            if err.errno in (errno.ENOENT, errno.ESRCH, 48):
                if pid_exists(self.pid):
                    raise AccessDenied(self.pid, self._name)
            raise

    @wrap_exceptions
    def nice_set(self, value):
        if self.pid in (2, 3):
            # Special case PIDs: internally setpriority(3) return ESRCH
            # (no such process), no matter what.
            # The process actually exists though, as it has a name,
            # creation time, etc.
            raise AccessDenied(self.pid, self._name)
        return cext_posix.setpriority(self.pid, value)

    @wrap_exceptions
    def ppid(self):
        return cext.proc_basic_info(self.pid)[0]

    @wrap_exceptions
    def uids(self):
        real, effective, saved, _, _, _ = cext.proc_cred(self.pid)
        return _common.puids(real, effective, saved)

    @wrap_exceptions
    def gids(self):
        _, _, _, real, effective, saved = cext.proc_cred(self.pid)
        return _common.puids(real, effective, saved)

    @wrap_exceptions
    def cpu_times(self):
        user, system = cext.proc_cpu_times(self.pid)
        return _common.pcputimes(user, system)

    @wrap_exceptions
    def terminal(self):
        psinfo = cext.proc_basic_info(self.pid)
        ttydev = psinfo[-1]
        # convert from 64-bit dev_t to 32-bit dev_t and then map the device
        ttydev = (((ttydev & 0x0000FFFF00000000) >> 16) | (ttydev & 0xFFFF))
        # try to match rdev of /dev/pts/* files ttydev
        for dev in glob.glob("/dev/**/*"):
            if os.stat(dev).st_rdev == ttydev:
                return dev
        return None

    @wrap_exceptions
    def cwd(self):
        try:
            return os.readlink("/proc/%s/cwd" % self.pid).rstrip('/')
        except OSError as err:
            if err.errno == errno.ENOENT:
                os.stat("/proc/%s" % self.pid)
                return None
            raise

    @wrap_exceptions
    def memory_info(self):
        ret = cext.proc_basic_info(self.pid)
        rss, vms = ret[1] * 1024, ret[2] * 1024
        return _common.pmem(rss, vms)

    memory_info_ex = memory_info

    @wrap_exceptions
    def status(self):
        code = cext.proc_basic_info(self.pid)[6]
        # XXX is '?' legit? (we're not supposed to return it anyway)
        return PROC_STATUSES.get(code, '?')

    def open_files(self):
        # TODO rewrite without using procfiles (stat /proc/pid/fd/* and then
        # find matching name of the inode)
        p = subprocess.Popen(["/usr/bin/procfiles", "-n", str(self.pid)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = p.communicate()
        if PY3:
            stdout, stderr = [x.decode(sys.stdout.encoding)
                              for x in (stdout, stderr)]
        if "no such process" in stderr:
            raise NoSuchProcess(self.pid, self._name)
        procfiles = re.findall("(\d+): S_IFREG.*\s*.*name:(.*)\n", stdout)
        retlist = []
        for fd, path in procfiles:
            path = path.strip()
            if path.startswith("//"):
                path = path[1:]
            if path == "Cannot be retrieved":
                continue
            retlist.append(_common.popenfile(path, int(fd)))
        return retlist

    @wrap_exceptions
    def num_fds(self):
        return len(os.listdir("/proc/%s/fd" % self.pid))

    @wrap_exceptions
    def num_ctx_switches(self):
        return _common.pctxsw(*cext.proc_num_ctx_switches(self.pid))

    @wrap_exceptions
    def wait(self, timeout=None):
        try:
            return _psposix.wait_pid(self.pid, timeout)
        except _psposix.TimeoutExpired:
            # support for private module import
            if TimeoutExpired is None:
                raise
            raise TimeoutExpired(timeout, self.pid, self._name)

    @wrap_exceptions
    def io_counters(self):
        rc, wc, rb, wb = cext.proc_io_counters(self.pid)
        return _common.pio(rc, wc, rb, wb)
