#include <cstdint>
#include "net.h"

struct net_device;

void configure_ip_address(net_device *dev, uint32_t address, uint32_t netmask);
