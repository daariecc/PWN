#include <stdint.h>

struct ioctl_struct {
	uint64_t addr;
	uint64_t value;
	uint64_t out;
};
