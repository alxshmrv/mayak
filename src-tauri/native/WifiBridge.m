#import <CoreLocation/CoreLocation.h>
#import <CoreWLAN/CoreWLAN.h>
#import <Foundation/Foundation.h>

#include <stdlib.h>
#include <string.h>

static CLLocationManager *MayakLocationManager(void) {
    static CLLocationManager *manager = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        manager = [[CLLocationManager alloc] init];
    });
    return manager;
}

static NSString *MayakSecurityName(CWSecurity security) {
    switch (security) {
        case kCWSecurityNone: return @"open";
        case kCWSecurityWEP: return @"wep";
        case kCWSecurityWPAPersonal: return @"wpa-personal";
        case kCWSecurityWPAPersonalMixed: return @"wpa-wpa2-personal";
        case kCWSecurityWPA2Personal: return @"wpa2-personal";
        case kCWSecurityPersonal: return @"personal";
        case kCWSecurityDynamicWEP: return @"dynamic-wep";
        case kCWSecurityWPAEnterprise: return @"wpa-enterprise";
        case kCWSecurityWPAEnterpriseMixed: return @"wpa-wpa2-enterprise";
        case kCWSecurityWPA2Enterprise: return @"wpa2-enterprise";
        case kCWSecurityEnterprise: return @"enterprise";
        case kCWSecurityWPA3Personal: return @"wpa3-personal";
        case kCWSecurityWPA3Enterprise: return @"wpa3-enterprise";
        case kCWSecurityWPA3Transition: return @"wpa2-wpa3-transition";
        case kCWSecurityOWE: return @"owe";
        case kCWSecurityOWETransition: return @"owe-transition";
        case kCWSecurityUnknown: return @"unknown";
        default: return @"unknown";
    }
}

static NSString *MayakPhyName(CWPHYMode mode) {
    switch (mode) {
        case kCWPHYModeNone: return @"unknown";
        case kCWPHYMode11a: return @"802.11a";
        case kCWPHYMode11b: return @"802.11b";
        case kCWPHYMode11g: return @"802.11g";
        case kCWPHYMode11n: return @"Wi-Fi 4";
        case kCWPHYMode11ac: return @"Wi-Fi 5";
        case kCWPHYMode11ax: return @"Wi-Fi 6";
        default: return @"unknown";
    }
}

static NSString *MayakBandName(CWChannelBand band) {
    switch (band) {
        case kCWChannelBand2GHz: return @"2.4 GHz";
        case kCWChannelBand5GHz: return @"5 GHz";
        case kCWChannelBand6GHz: return @"6 GHz";
        case kCWChannelBandUnknown: return @"unknown";
        default: return @"unknown";
    }
}

static NSString *MayakWidthName(CWChannelWidth width) {
    switch (width) {
        case kCWChannelWidth20MHz: return @"20 MHz";
        case kCWChannelWidth40MHz: return @"40 MHz";
        case kCWChannelWidth80MHz: return @"80 MHz";
        case kCWChannelWidth160MHz: return @"160 MHz";
        case kCWChannelWidthUnknown: return @"unknown";
        default: return @"unknown";
    }
}

void mayak_request_location_permission(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [MayakLocationManager() requestWhenInUseAuthorization];
    });
}

int32_t mayak_location_authorization_status(void) {
    __block CLAuthorizationStatus status = kCLAuthorizationStatusNotDetermined;
    if ([NSThread isMainThread]) {
        status = MayakLocationManager().authorizationStatus;
    } else {
        dispatch_sync(dispatch_get_main_queue(), ^{
            status = MayakLocationManager().authorizationStatus;
        });
    }
    return (int32_t)status;
}

char *mayak_copy_wifi_json(void) {
    @autoreleasepool {
        CWWiFiClient *client = [CWWiFiClient sharedWiFiClient];
        CWInterface *interface = [client interface];
        NSMutableDictionary *result = [NSMutableDictionary dictionary];

        if (interface == nil) {
            result[@"available"] = @NO;
        } else {
            result[@"available"] = @YES;
            result[@"interfaceName"] = interface.interfaceName ?: [NSNull null];
            result[@"powerOn"] = @(interface.powerOn);
            result[@"ssid"] = interface.ssid ?: [NSNull null];
            result[@"bssid"] = interface.bssid ?: [NSNull null];
            result[@"rssi"] = @(interface.rssiValue);
            result[@"noise"] = @(interface.noiseMeasurement);
            result[@"transmitRate"] = @(interface.transmitRate);
            result[@"countryCode"] = interface.countryCode ?: [NSNull null];
            result[@"security"] = MayakSecurityName(interface.security);
            result[@"phyMode"] = MayakPhyName(interface.activePHYMode);

            CWChannel *channel = interface.wlanChannel;
            if (channel != nil) {
                result[@"channel"] = @{
                    @"number": @(channel.channelNumber),
                    @"band": MayakBandName(channel.channelBand),
                    @"width": MayakWidthName(channel.channelWidth)
                };
            } else {
                result[@"channel"] = [NSNull null];
            }
        }

        NSError *error = nil;
        NSData *data = [NSJSONSerialization dataWithJSONObject:result options:0 error:&error];
        if (data == nil || error != nil) {
            return NULL;
        }

        size_t length = data.length;
        char *buffer = malloc(length + 1);
        if (buffer == NULL) {
            return NULL;
        }
        memcpy(buffer, data.bytes, length);
        buffer[length] = '\0';
        return buffer;
    }
}

void mayak_free_string(char *value) {
    free(value);
}
