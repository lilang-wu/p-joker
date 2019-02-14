//
//  IOkitConnection.h
//  pyiokit_wrapper
//
//  Created by lilang_wu on 2018/5/4.
//  Copyright © 2018年 lilang_wu. All rights reserved.
//

#ifndef IOkitConnection_h
#define IOkitConnection_h

#include "IOKitConnectionBase.h"

#include <iostream>

class IOKitConnection : public IOKitConnectionBase, public boost::python::wrapper<IOKitConnectionBase> {
public:
    IOKitConnection(std::string target) : IOKitConnectionBase(target) {
        
    };
};


#endif /* IOkitConnection_h */
