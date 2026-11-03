#import "capture_ios_guard.h"

@implementation SaltsCaptureGuard {
    NSLock *_lock;
    void *_capture;
    salts_ios_capture_finalizer _finalizer;
    NSUInteger _references;
    BOOL _acceptingCallbacks;
}

- (instancetype)initWithCapture:(void *)capture
                       finalizer:(salts_ios_capture_finalizer)finalizer {
    self = [super init];
    if (self) {
        _lock = [[NSLock alloc] init];
        _capture = capture;
        _finalizer = finalizer;
        _references = 1;
        _acceptingCallbacks = YES;
    }
    return self;
}

- (void *)acquireCapture {
    void *capture = NULL;
    [_lock lock];
    if (_acceptingCallbacks) {
        ++_references;
        capture = _capture;
    }
    [_lock unlock];
    return capture;
}

- (void)releaseCapture {
    void *capture = NULL;
    salts_ios_capture_finalizer finalizer = NULL;

    [_lock lock];
    if (_references > 0 && --_references == 0) {
        capture = _capture;
        _capture = NULL;
        finalizer = _finalizer;
    }
    [_lock unlock];

    if (capture && finalizer) finalizer(capture);
}

- (void)detachOwner {
    void *capture = NULL;
    salts_ios_capture_finalizer finalizer = NULL;

    [_lock lock];
    if (_acceptingCallbacks) {
        _acceptingCallbacks = NO;
        if (_references > 0 && --_references == 0) {
            capture = _capture;
            _capture = NULL;
            finalizer = _finalizer;
        }
    }
    [_lock unlock];

    if (capture && finalizer) finalizer(capture);
}

@end
