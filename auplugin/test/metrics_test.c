#include <stdio.h>
#include <auplugin.h>

static void cb(unsigned int depth, unsigned int max, int ovf)
{
    printf("depth=%u max=%u ovf=%d\n", depth, max, ovf);
}

int main(void)
{
    auplugin_register_stats_callback(cb);
    auplugin_report_stats();
    return 0;
}

