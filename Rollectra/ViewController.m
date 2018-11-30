//
//  ViewController.m
//  Rollectra
//
//  Created by pwn20wnd on 8/29/18.
//  Copyright © 2018 Pwn20wnd. All rights reserved.
//

#include <sys/stat.h>
#include <spawn.h>
#include <sys/attr.h>
#include <sys/snapshot.h>
#include <dlfcn.h>
#import "ViewController.h"
#include "common.h"
#ifndef WANT_CYDIA
#include "offsets.h"
#include "sploit.h"
#include "kmem.h"
#endif    /* WANT_CYDIA */
#include "QiLin.h"
#include "iokit.h"

@interface ViewController ()

@end

@implementation ViewController

#ifndef WANT_CYDIA

// https://github.com/JonathanSeals/kernelversionhacker/blob/3dcbf59f316047a34737f393ff946175164bf03f/kernelversionhacker.c#L92

#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC 0xfeedfacf
#define MAX_KASLR_SLIDE 0x21000000
#define KERNEL_SEARCH_ADDRESS_IOS10 0xfffffff007004000

#define ptrSize sizeof(uintptr_t)

static vm_address_t get_kernel_base(mach_port_t tfp0) {
    uint64_t addr = 0;
    addr = KERNEL_SEARCH_ADDRESS_IOS10+MAX_KASLR_SLIDE;
    
    while (1) {
        char *buf;
        mach_msg_type_number_t sz = 0;
        kern_return_t ret = vm_read(tfp0, addr, 0x200, (vm_offset_t*)&buf, &sz);
        
        if (ret) {
            goto next;
        }
        
        if (*((uint32_t *)buf) == MACHO_HEADER_MAGIC) {
            int ret = vm_read(tfp0, addr, 0x1000, (vm_offset_t*)&buf, &sz);
            if (ret != KERN_SUCCESS) {
                printf("Failed vm_read %i\n", ret);
                goto next;
            }
            
            for (uintptr_t i=addr; i < (addr+0x2000); i+=(ptrSize)) {
                mach_msg_type_number_t sz;
                int ret = vm_read(tfp0, i, 0x120, (vm_offset_t*)&buf, &sz);
                
                if (ret != KERN_SUCCESS) {
                    printf("Failed vm_read %i\n", ret);
                    exit(-1);
                }
                if (!strcmp(buf, "__text") && !strcmp(buf+0x10, "__PRELINK_TEXT")) {
                    return addr;
                }
            }
        }
        
    next:
        addr -= 0x200000;
    }
}
#endif    /* WANT_CYDIA */

int sha1_to_str(const unsigned char *hash, int hashlen, char *buf, size_t buflen)
{
    if (buflen < (hashlen*2+1)) {
        return -1;
    }
    
    int i;
    for (i=0; i<hashlen; i++) {
        sprintf(buf+i*2, "%02X", hash[i]);
    }
    buf[i*2] = 0;
    return ERR_SUCCESS;
}

char *copyBootHash(void)
{
    io_registry_entry_t chosen = IORegistryEntryFromPath(kIOMasterPortDefault, "IODeviceTree:/chosen");
    
    if (!MACH_PORT_VALID(chosen)) {
        printf("Unable to get IODeviceTree:/chosen port\n");
        return NULL;
    }
    
    CFDataRef hash = (CFDataRef)IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, 0);
    
    IOObjectRelease(chosen);
    
    if (hash == nil) {
        fprintf(stderr, "Unable to read boot-manifest-hash\n");
        return NULL;
    }
    
    if (CFGetTypeID(hash) != CFDataGetTypeID()) {
        fprintf(stderr, "Error hash is not data type\n");
        CFRelease(hash);
        return NULL;
    }
    
    // Make a hex string out of the hash
    
    CFIndex length = CFDataGetLength(hash) * 2 + 1;
    char *manifestHash = (char*)calloc(length, sizeof(char));
    
    int ret = sha1_to_str(CFDataGetBytePtr(hash), (int)CFDataGetLength(hash), manifestHash, length);
    
    CFRelease(hash);
    
    if (ret != ERR_SUCCESS) {
        printf("Unable to generate bootHash string\n");
        free(manifestHash);
        return NULL;
    }
    
    return manifestHash;
}

#define APPLESNAP "com.apple.os.update-"

const char *systemSnapshot(char *bootHash) {
    if (!bootHash) {
        return NULL;
    }
    return [[NSString stringWithFormat:@APPLESNAP @"%s", bootHash] UTF8String];
}

typedef struct val_attrs {
    uint32_t          length;
    attribute_set_t   returned;
    attrreference_t   name_info;
} val_attrs_t;

int snapshot_check(const char *vol, const char *name)
{
    struct attrlist attr_list = { 0 };
    
    attr_list.commonattr = ATTR_BULK_REQUIRED;
    
    char *buf = (char*)calloc(2048, sizeof(char));
    int retcount;
    int fd = open(vol, O_RDONLY, 0);
    while ((retcount = fs_snapshot_list(fd, &attr_list, buf, 2048, 0))>0) {
        char *bufref = buf;
        
        for (int i=0; i<retcount; i++) {
            val_attrs_t *entry = (val_attrs_t *)bufref;
            if (entry->returned.commonattr & ATTR_CMN_NAME) {
                printf("%s\n", (char*)(&entry->name_info) + entry->name_info.attr_dataoffset);
                if (strstr((char*)(&entry->name_info) + entry->name_info.attr_dataoffset, name))
                    return 1;
            }
            bufref += entry->length;
        }
    }
    free(buf);
    close(fd);
    
    if (retcount < 0) {
        perror("fs_snapshot_list");
        return -1;
    }
    
    return 0;
}

// https://github.com/tihmstar/doubleH3lix/blob/4428c660832e98271f5d82f7a9c67e842b814621/doubleH3lix/jailbreak.mm#L645

extern char* const* environ;
int easyPosixSpawn(NSURL *launchPath,NSArray *arguments) {
    NSMutableArray *posixSpawnArguments=[arguments mutableCopy];
    [posixSpawnArguments insertObject:[launchPath lastPathComponent] atIndex:0];
    
    int argc=(int)posixSpawnArguments.count+1;
    printf("Number of posix_spawn arguments: %d\n",argc);
    char **args=(char**)calloc(argc,sizeof(char *));
    
    for (int i=0; i<posixSpawnArguments.count; i++)
        args[i]=(char *)[posixSpawnArguments[i]UTF8String];
    
    printf("File exists at launch path: %d\n",[[NSFileManager defaultManager]fileExistsAtPath:launchPath.path]);
    printf("Executing %s: %s\n",launchPath.path.UTF8String,arguments.description.UTF8String);
    
    posix_spawn_file_actions_t action;
    posix_spawn_file_actions_init(&action);
    
    pid_t pid;
    int status;
    status = posix_spawn(&pid, launchPath.path.UTF8String, &action, NULL, args, environ);
    
    if (status == 0) {
        if (waitpid(pid, &status, 0) != -1) {
            // wait
        }
    }
    
    posix_spawn_file_actions_destroy(&action);
    free(args);
    
    return status;
}

int waitForFile(const char *filename) {
    int rv = 0;
    rv = access(filename, F_OK);
    for (int i = 0; !(i >= 100 || rv == 0); i++) {
        usleep(100000);
        rv = access(filename, F_OK);
    }
    return rv;
}

#ifdef WANT_CYDIA
void unjailbreak(int shouldEraseUserData)
#else    /* !WANT_CYDIA */
void unjailbreak(mach_port_t tfp0, uint64_t kernel_base, int shouldEraseUserData)
#endif    /* !WANT_CYDIA */
{
    // Initialize variables.
    int rv = 0;
#ifndef WANT_CYDIA
    uint64_t myOriginalCredAddr = 0;
#endif    /* WANT_CYDIA */
    
#ifndef WANT_CYDIA
    // Initialize QiLin.
    LOG("%@", NSLocalizedString(@"Initializing QiLin...", nil));
    rv = initQiLin(tfp0, kernel_base);
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    LOG("%@", NSLocalizedString(@"Successfully initialized QiLin.", nil));
#endif    /* WANT_CYDIA */
    
#ifndef WANT_CYDIA
    // Rootify myself.
    LOG("%@", NSLocalizedString(@"Rootifying myself...", nil));
    rv = rootifyMe();
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    LOG("%@", NSLocalizedString(@"Successfully rootified myself.", nil));
#endif    /* WANT_CYDIA */
    
#ifndef WANT_CYDIA
    // Escape Sandbox.
    LOG("%@", NSLocalizedString(@"Escaping Sandbox...", nil));
    myOriginalCredAddr = ShaiHuludMe(0);
    LOG("myOriginalCredAddr: " ADDR "\n", myOriginalCredAddr);
    LOG("%@", NSLocalizedString(@"Successfully escaped Sandbox.", nil));
#endif    /* WANT_CYDIA */
    
#ifndef WANT_CYDIA
    // Write a test file.
    
    LOG("%@", NSLocalizedString(@"Writing a test file...", nil));
    if (!access("/var/mobile/test.txt", F_OK)) {
        rv = unlink("/var/mobile/test.txt");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
    }
    rv = fclose(fopen("/var/mobile/test.txt", "w+"));
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    rv = unlink("/var/mobile/test.txt");
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    LOG("%@", NSLocalizedString(@"Successfully wrote a test file.", nil));
#endif    /* WANT_CYDIA */
    
#ifndef WANT_CYDIA
    // Borrow entitlements from fsck_apfs.
    
    LOG("%@", NSLocalizedString(@"Borrowing entitlements from fsck_apfs...", nil));
    borrowEntitlementsFromDonor("/sbin/fsck_apfs", NULL);
    LOG("%@", NSLocalizedString(@"Successfully borrowed entitlements from fsck_apfs.", nil));
    
    // We now have fs_snapshot_rename.
#endif    /* WANT_CYDIA */
    
    // Revert to the system snapshot.
    LOG("%@", NSLocalizedString(@"Reverting to the system snapshot...", nil));
    extern int SBDataReset(mach_port_t, int);
    extern mach_port_t SBSSpringBoardServerPort(void);
    mach_port_t SpringBoardServerPort = SBSSpringBoardServerPort();
    _assert(MACH_PORT_VALID(SpringBoardServerPort));
#ifdef WANT_CYDIA
    if (kCFCoreFoundationVersionNumber < 1452.23) {
        if (access("/var/MobileSoftwareUpdate/mnt1", F_OK)) {
            rv = mkdir("/var/MobileSoftwareUpdate/mnt1", 0755);
            LOG("rv: " "%d" "\n", rv);
            _assert(rv == 0);
        }
        if (snapshot_check("/", "electra-prejailbreak") == 1) {
            rv = easyPosixSpawn([NSURL fileURLWithPath:@"/sbin/mount_apfs"], @[@"-s", @"electra-prejailbreak", @"/", @"/var/MobileSoftwareUpdate/mnt1"]);
        } else if (snapshot_check("/", "orig-fs") == 1) {
            rv = easyPosixSpawn([NSURL fileURLWithPath:@"/sbin/mount_apfs"], @[@"-s", @"orig-fs", @"/", @"/var/MobileSoftwareUpdate/mnt1"]);
        } else {
            rv = easyPosixSpawn([NSURL fileURLWithPath:@"/sbin/mount_apfs"], @[@"-s", [NSString stringWithFormat:@"%s", systemSnapshot(copyBootHash())], @"/", @"/var/MobileSoftwareUpdate/mnt1"]);
        }
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = waitForFile("/var/MobileSoftwareUpdate/mnt1/sbin/launchd");
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
        rv = easyPosixSpawn([NSURL fileURLWithPath:@"/usr/bin/rsync"], @[@"-vaxcH", @"--progress", @"--delete-after", @"/var/MobileSoftwareUpdate/mnt1/.", @"/"]);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
    }
    else {
#endif    /* !WANT_CYDIA */
#ifdef WANT_CYDIA
        rv = fs_snapshot_rename(open("/", O_RDONLY, 0), "orig-fs", systemSnapshot(copyBootHash()), 0);
        LOG("rv: " "%d" "\n", rv);
        _assert(rv == 0);
    }
#endif    /* !WANT_CYDIA */
    LOG("%@", NSLocalizedString(@"Successfully put the system snapshot in place, it should revert on the next mount.", nil));
    
#ifndef WANT_CYDIA
    // Entitle myself.
    LOG("%@", NSLocalizedString(@"Entitling myself...", nil));
    rv = entitleMe("\t<key>platform-application</key>\n"
                   "\t<true/>\n"
                   "\t<key>com.apple.springboard.wipedevice</key>\n"
                   "\t<true/>");
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    LOG("%@", NSLocalizedString(@"Successfully entitled myself.", nil));
#endif    /* WANT_CYDIA */
    
    // Erase user data.
    LOG("%@", NSLocalizedString(@"Erasing user data...", nil));
    rv = SBDataReset(SpringBoardServerPort, shouldEraseUserData ? 5 : 1);
    LOG("rv: " "%d" "\n", rv);
    _assert(rv == 0);
    LOG("%@", NSLocalizedString(@"Successfully erased user data.", nil));
}

- (IBAction)tappedOnUnjailbreak:(id)sender {
    UIAlertController *alertController = [UIAlertController alertControllerWithTitle:NSLocalizedString(@"Confirmation", nil) message:NSLocalizedString(@"Are you sure want to erase all data and unjailbreak the device?", nil) preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *OK = [UIAlertAction actionWithTitle:NSLocalizedString(@"Erase All", nil) style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.unjailbreakButton setEnabled:NO];
            });
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.unjailbreakButton setAlpha:0.5];
            });
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.resetUserDataSwitch setEnabled:NO];
            });
#ifndef WANT_CYDIA
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.unjailbreakButton setTitle:NSLocalizedString(@"Exploiting...", nil) forState:UIControlStateDisabled];
            });
#endif    /* WANT_CYDIA */
#ifndef WANT_CYDIA
            // Initialize kernel exploit.
            LOG("%@", NSLocalizedString(@"Initializing kernel exploit...", nil));
            vfs_sploit();
#endif    /* WANT_CYDIA */
#ifndef WANT_CYDIA
            // Validate TFP0.
            LOG("%@", NSLocalizedString(@"Validating TFP0...", nil));
            _assert(MACH_PORT_VALID(tfp0));
            LOG("%@", NSLocalizedString(@"Successfully validated TFP0.", nil));
#endif    /* WANT_CYDIA */
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.unjailbreakButton setTitle:NSLocalizedString(@"Unjailbreaking...", nil) forState:UIControlStateDisabled];
            });
#ifdef WANT_CYDIA
            dispatch_async(dispatch_get_main_queue(), ^{
                unjailbreak(self.resetUserDataSwitch.isOn);
            });
#else    /* !WANT_CYDIA */
            dispatch_async(dispatch_get_main_queue(), ^{
                unjailbreak(tfp0, (uint64_t)get_kernel_base(tfp0), self.resetUserDataSwitch.isOn);
            });
#endif    /* !WANT_CYDIA */
            dispatch_async(dispatch_get_main_queue(), ^{
                [self.unjailbreakButton setTitle:NSLocalizedString(@"Failed, reboot.", nil) forState:UIControlStateDisabled];
            });
        });
    }];
    UIAlertAction *Cancel = [UIAlertAction actionWithTitle:NSLocalizedString(@"Cancel", nil) style:UIAlertActionStyleDefault handler:nil];
    [alertController addAction:OK];
    [alertController addAction:Cancel];
    [alertController setPreferredAction:Cancel];
    [self presentViewController:alertController animated:YES completion:nil];
}
    
+ (NSURL *)getURLForUserName:(NSString *)userName {
    if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"tweetbot://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"tweetbot:///user_profile/%@", userName]];
    } else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"twitterrific://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"twitterrific:///profile?screen_name=%@", userName]];
    } else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"tweetings://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"tweetings:///user?screen_name=%@", userName]];
    } else if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"twitter://"]]) {
        return [NSURL URLWithString:[NSString stringWithFormat:@"https://mobile.twitter.com/%@", userName]];
    } else {
        return [NSURL URLWithString:[NSString stringWithFormat:@"https://mobile.twitter.com/%@", userName]];
    }
}
    
- (IBAction)tappedOnMe:(id)sender {
    [[UIApplication sharedApplication] openURL:[ViewController getURLForUserName:@"Pwn20wnd"] options:@{} completionHandler:nil];
}
    
- (IBAction)tappedOnAesign_:(id)sender {
    [[UIApplication sharedApplication] openURL:[ViewController getURLForUserName:@"aesign_"] options:@{} completionHandler:nil];
}

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    NSMutableAttributedString *str = [[NSMutableAttributedString alloc] initWithString:@"Revert all changes,\nfor a stock iOS."];
    [str addAttribute:NSFontAttributeName value:[UIFont systemFontOfSize:19 weight:UIFontWeightBold] range:[@"Revert all changes,\nfor a stock iOS." rangeOfString:@"Revert "]];
    [str addAttribute:NSFontAttributeName value:[UIFont systemFontOfSize:19 weight:UIFontWeightMedium] range:[@"Revert all changes,\nfor a stock iOS." rangeOfString:@"all changes,\nfor a stock "]];
    [str addAttribute:NSFontAttributeName value:[UIFont systemFontOfSize:19 weight:UIFontWeightBold] range:[@"Revert all changes,\nfor a stock iOS." rangeOfString:@"iOS."]];
    [self.infoLabel setAttributedText:str];
    [self.unjailbreakButton addTarget:self action:@selector(tappedOnUnjailbreak:) forControlEvents:UIControlEventTouchUpInside];
    [self.myButton addTarget:self action:@selector(tappedOnMe:) forControlEvents:UIControlEventTouchUpInside];
    [self.aesign_Button addTarget:self action:@selector(tappedOnAesign_:) forControlEvents:UIControlEventTouchUpInside];
#ifndef WANT_CYDIA
    [self.QiLinLabel setHidden:NO];
#endif    /* WANT_CYDIA */
#ifdef WANT_CYDIA
    if (kCFCoreFoundationVersionNumber < 1443.00) {
#else    /* !WANT_CYDIA */
    if (kCFCoreFoundationVersionNumber <= 1451.51) {
#endif    /* !WANT_CYDIA */
        dispatch_async(dispatch_get_main_queue(), ^{
            [self.unjailbreakButton setEnabled:NO];
            [self.unjailbreakButton setTitle:NSLocalizedString(@"Incompatible version", nil) forState:UIControlStateDisabled];
            [self.unjailbreakButton setAlpha:0.5];
            [self.resetUserDataSwitch setEnabled:NO];
        });
    }
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleLightContent;
}

@end
