//
//  IOKitConnectionBase.h
//  pyiokit_wrapper
//
//  Created by lilang_wu on 2018/5/4.
//  Copyright © 2018年 lilang_wu. All rights reserved.
//

#ifndef IOKitConnectionBase_h
#define IOKitConnectionBase_h

#include <boost/python.hpp>
#include <string.h>
#include <mach/port.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOKitLib.h>

class IOKitConnectionBase {
    
public:
    
    IOKitConnectionBase(std::string target);
    kern_return_t  fuzz_ServiceOpen(char* servicename, int type);
    kern_return_t  fuzz_IOConnectCallMethod(int selector, const uint64_t *input, uint32_t inputCont, const void *inputStruct, size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, void *outputStruct, size_t *outputStructCntP);
    kern_return_t  fuzz_IOConnectCallAsyncMethod(int selector, unsigned int wakePort, uint64_t *reference, uint32_t referenceCont, const uint64_t *input, uint32_t inputCont, const void *inputStruct, size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, void *outputStruct, size_t *outputStructCntP);
    //kern_return_t fuzz_IOServiceAddNotification(char* notificationType, );
private:
    io_connect_t connect;
};



#endif /* IOKitConnectionBase_h */
