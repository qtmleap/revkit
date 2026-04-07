#import <Orion/Orion.h>
#import <os/log.h>

__attribute__((constructor)) static void init() {
    // Initialize Orion - do not remove this line.
    orion_init();
    NSLog(@"[NFXBypass] NetflixSSLBypass loaded");
    os_log_t log = os_log_create("dev.tkgstrator.charon", "tweak");
    os_log(log, "[NFXBypass] NetflixSSLBypass loaded (os_log)");
}
