#ifndef APC_H
#define APC_H

#define PSE51_LO_SIGNAL_REQ 0
#define PSE51_LO_FREE_REQ   1

void pse51_schedule_lostage(int request, void *arg, size_t size);

int pse51_apc_pkg_init(void);

void pse51_apc_pkg_cleanup(void);

#endif /* APC_H */
