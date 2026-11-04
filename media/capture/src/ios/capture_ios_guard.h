#ifndef SALTS_CAPTURE_IOS_GUARD_H
#define SALTS_CAPTURE_IOS_GUARD_H

#import <Foundation/Foundation.h>

typedef void (*salts_ios_capture_finalizer)(void *capture);

@interface SaltsCaptureGuard : NSObject

- (instancetype)initWithCapture:(void *)capture
                       finalizer:(salts_ios_capture_finalizer)finalizer;
- (void *)acquireCapture;
- (void)releaseCapture;
- (void)detachOwner;

@end

#endif
