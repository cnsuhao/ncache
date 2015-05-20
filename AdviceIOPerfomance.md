some advice:
we can modify some Linux system params to improve the device I/O perfomance.

for example:
/proc/sys/vm/dirty\_writeback\_centisecs
> echo "100" > /proc/sys/vm/dirty\_writeback\_centisecs

/proc/sys/vm/dirty\_ratio
> echo '10' > /proc/sys/vm/dirty\_ratio

/proc/sys/vm/dirty\_background\_ratio
> echo '5' > /proc/sys/vm/dirty\_background\_ratio