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
    ~IOKitConnectionBase();
    kern_return_t  fuzz_ServiceOpen(char* servicename, int type);
    kern_return_t  fuzz_IOConnectCallMethod(int selector, boost::python::object input, uint32_t inputCont, boost::python::object inputStruct, size_t inputStructCnt);
    kern_return_t  fuzz_IOConnectCallAsyncMethod(int selector, unsigned int wakePort, uint64_t *reference, uint32_t referenceCont,boost::python::object input, uint32_t inputCont, boost::python::object inputStruct, size_t inputStructCnt);
    //kern_return_t fuzz_IOServiceAddNotification(char* notificationType, );
    
    
    boost::python::list  getfuzz_output();
    boost::python::list getfuzz_outputStruct();
    
private:
    io_connect_t connect;
    uint64_t     *fuzz_output;       // Out
    uint32_t     fuzz_outputCnt;     // In/Out
    uint64_t     *fuzz_outputStruct;       // Out
    size_t       fuzz_outputStructCnt;   // In/Out
    
};



#endif /* IOKitConnectionBase_h */
