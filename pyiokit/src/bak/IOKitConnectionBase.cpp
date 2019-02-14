//
//  main.m
//  pyiokit_wrapper
//
//  Created by lilang_wu on 2018/5/4.
//  Copyright © 2018年 lilang_wu. All rights reserved.
//

#include "IOKitConnectionBase.h"


IOKitConnectionBase::IOKitConnectionBase(std::string target){
    
}

kern_return_t IOKitConnectionBase::fuzz_ServiceOpen(char* servicename, int type){
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOUSBInterface"));
    printf("IOKitConnectionBase: get service name 0x%x\n", service);
    kern_return_t ret = IOServiceOpen(service, mach_task_self(), 0, &connect);
    if (ret != KERN_SUCCESS) {
        printf("IOKitConnectionBase: unable to get user client connection\n");
        return 0;
    }
    printf("IOKitConnectionBase: get user client connection 0x%x\n", connect);
    return KERN_SUCCESS;
}

kern_return_t  IOKitConnectionBase::fuzz_IOConnectCallMethod(int selector, const uint64_t *input, uint32_t inputCont, const void *inputStruct, size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, void *outputStruct, size_t *outputStructCntP){
      try {
    kern_return_t ret = IOConnectCallMethod(connect, selector, input, inputCont, inputStruct, inputStructCnt, output, outputCnt, outputStruct, outputStructCntP);
    
    if (ret != KERN_SUCCESS) {
        printf("fuzz_IOConnectCallMethod: error code 0x%x\n", ret);
        return ret;
    }
          
      } catch(boost::python::error_already_set const&) {
        PyErr_Print();
    }
    return KERN_SUCCESS;
}

kern_return_t  IOKitConnectionBase::fuzz_IOConnectCallAsyncMethod(int selector, unsigned int wakePort, uint64_t *reference, uint32_t referenceCont, const uint64_t *input, uint32_t inputCont, const void *inputStruct, size_t inputStructCnt, uint64_t *output, uint32_t *outputCnt, void *outputStruct, size_t *outputStructCntP){
    
    kern_return_t ret = IOConnectCallAsyncMethod(connect, selector, wakePort, reference, referenceCont, input, inputCont, inputStruct, inputStructCnt, output, outputCnt, outputStruct, outputStructCntP);
    
    if (ret != KERN_SUCCESS) {
        printf("fuzz_IOConnectCallMethod: error code 0x%x\n", ret);
        return ret;
    }
    return KERN_SUCCESS;
    
}
