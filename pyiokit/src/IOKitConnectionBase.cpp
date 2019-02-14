//
//  main.m
//  pyiokit_wrapper
//
//  Created by lilang_wu on 2018/5/4.
//  Copyright © 2018年 lilang_wu. All rights reserved.
//

#include "IOKitConnectionBase.h"
#include <numpy/arrayobject.h>


IOKitConnectionBase::IOKitConnectionBase(std::string target){
    
}

IOKitConnectionBase::~IOKitConnectionBase(){
    IOServiceClose(connect);
    fuzz_output = 0;
    fuzz_outputStruct = 0;
}


kern_return_t IOKitConnectionBase::fuzz_ServiceOpen(char* servicename, int type){
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(servicename));
    //printf("IOKitConnectionBase: Service %s: get service name 0x%x\n", servicename, service);
    kern_return_t ret = IOServiceOpen(service, mach_task_self(), type, &connect);
    if (ret != KERN_SUCCESS) {
        //printf("IOKitConnectionBase: Service %s: unable to get user client connection\n", servicename);
        return -1;
    }
    //printf("IOKitConnectionBase: Service %s: get user client connection 0x%x\n", servicename, connect);
    return KERN_SUCCESS;
}


kern_return_t  IOKitConnectionBase::fuzz_IOConnectCallMethod(int selector, boost::python::object input, uint32_t inputCont, boost::python::object inputStruct, size_t inputStructCnt){
    
    PyArrayObject* input_data_arr = reinterpret_cast<PyArrayObject*>(input.ptr());
    uint64_t * input_data = static_cast<uint64_t *>(PyArray_DATA(input_data_arr));
    
    PyArrayObject* inputStruct_data_arr = reinterpret_cast<PyArrayObject*>(inputStruct.ptr());
    uint64_t * inputStruct_data = static_cast<uint64_t *>(PyArray_DATA(inputStruct_data_arr));
    
    try {
        kern_return_t ret = IOConnectCallMethod(connect, selector, input_data, inputCont, inputStruct_data, inputStructCnt, fuzz_output, &fuzz_outputCnt, fuzz_outputStruct, &fuzz_outputStructCnt);
        
        if (ret != KERN_SUCCESS) {
            printf("fuzz_IOConnectCallMethod: error code 0x%x\n", ret);
            return ret;
        }
        
    } catch(boost::python::error_already_set const&) {
        PyErr_Print();
    }
    return KERN_SUCCESS;
}


kern_return_t  IOKitConnectionBase::fuzz_IOConnectCallAsyncMethod(int selector, unsigned int wakePort, uint64_t *reference, uint32_t referenceCont,boost::python::object input, uint32_t inputCont, boost::python::object inputStruct, size_t inputStructCnt){
    
    PyArrayObject* input_data_arr = reinterpret_cast<PyArrayObject*>(input.ptr());
    uint64_t * input_data = static_cast<uint64_t *>(PyArray_DATA(input_data_arr));
    
    PyArrayObject* inputStruct_data_arr = reinterpret_cast<PyArrayObject*>(inputStruct.ptr());
    uint64_t * inputStruct_data = static_cast<uint64_t *>(PyArray_DATA(inputStruct_data_arr));
    
    
    try {
        kern_return_t ret = IOConnectCallAsyncMethod(connect, selector, wakePort, NULL, 0, input_data, inputCont, inputStruct_data, inputStructCnt, fuzz_output, &fuzz_outputCnt, fuzz_outputStruct, &fuzz_outputStructCnt);
    
        if (ret != KERN_SUCCESS) {
            printf("fuzz_IOConnectCallMethod: error code 0x%x\n", ret);
            return ret;
        }
    } catch(boost::python::error_already_set const&) {
        PyErr_Print();
    }
    return KERN_SUCCESS;
}


boost::python::list IOKitConnectionBase::getfuzz_output(){
    printf("fuzz_IOConnectCallMethod: fuzz_outputCnt = 0x%x\n", fuzz_outputCnt);
    
    __block boost::python::list out_list;
    if (fuzz_outputCnt && *fuzz_output) {
        for (int i = 0; i < fuzz_outputCnt > 16? 16:fuzz_outputCnt; i++) {
            out_list.append(fuzz_output[i]);
            //printf("fuzz_IOConnectCallMethod: out_list[%d] = 0x%d\n", i, fuzz_output[i]);
        }
    } else {
        printf("fuzz_IOConnectCallMethod: fuzz_output is null\n");
    }
    
    return out_list;
}


boost::python::list IOKitConnectionBase::getfuzz_outputStruct(){
    printf("fuzz_IOConnectCallMethod: fuzz_outputStructCnt = 0x%x\n", fuzz_outputStructCnt);
    
    __block boost::python::list out_list;
    if (fuzz_outputStructCnt && *fuzz_outputStruct) {
        for (int i = 0; i < fuzz_outputStructCnt > 16? 16:fuzz_outputStructCnt; i++) {
            out_list[i] = fuzz_outputStruct[i];
        }
    } else {
        printf("fuzz_IOConnectCallMethod: fuzz_outputStruct is null\n");
    }
    
    return out_list;
}

