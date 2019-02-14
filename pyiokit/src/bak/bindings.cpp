//
//  bindings.cpp
//  pyiokit_wrapper
//
//  Created by lilang_wu on 2018/5/4.
//  Copyright © 2018年 lilang_wu. All rights reserved.
//


#include <boost/python.hpp>
#include <boost/python/suite/indexing/map_indexing_suite.hpp>
#include <boost/python/overloads.hpp>
#include <boost/python/raw_function.hpp>

#include "IOKitConnection.h"

using namespace boost::python;

BOOST_PYTHON_MODULE(iokitconnection) {
    PyEval_InitThreads();
    
    class_<IOKitConnection, boost::noncopyable>("IOKitConnection", init<std::string>())
    
    .def("fuzz_IOServiceOpen", &IOKitConnection::fuzz_ServiceOpen)
    .def("fuzz_IOConnectCallMethod", &IOKitConnection::fuzz_IOConnectCallMethod)
    .def("fuzz_IOConnectCallAsyncMethod", &IOKitConnection::fuzz_IOConnectCallAsyncMethod)
    ;
    
}
