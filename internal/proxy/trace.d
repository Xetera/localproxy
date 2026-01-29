#pragma D option quiet
#pragma D option bufsize=8m
#pragma D option strsize=4k

syscall::writev:entry,
syscall::write:entry
/pid == $1 && (arg0 == 1 || arg0 == 2)/
{
  printf("%s %s", arg0 == 1 ? "1" : "0", copyinstr(arg1));
}
