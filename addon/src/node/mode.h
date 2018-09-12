
#ifndef CRYPTIAN_ADDON_MODE_H_
#define CRYPTIAN_ADDON_MODE_H_

#include <nan.h>
#include <algorithm-block.h>
#include "algorithm.h"

using namespace v8;

namespace cryptian {

class ModeBase: public node::ObjectWrap {
protected:
    static Nan::Persistent<Function> constructor;

    static NAN_METHOD(New) {
        Nan::ThrowTypeError("Invalid usage. This method is abstract.");
        return info.GetReturnValue().Set(Nan::Undefined());
    }
    
public:
    static Handle<FunctionTemplate> getFunctionTemplate() {

        Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(New);
        tpl->SetClassName(Nan::New("Mode").ToLocalChecked());

        constructor.Reset(tpl->GetFunction());

        return tpl;
    }

};

template <typename T>
class Mode: public node::ObjectWrap {
protected:
    Mode(algorithm::AlgorithmBlock* algorithm, std::vector<char> iv) {

        mode = new T();
        mode->setAlgorithm(algorithm);
        mode->setIv(iv);
    }

    T* mode;

    static void freeBuffer(char *buffer, void *hint) {
        delete[] buffer;
    }

    static std::vector<char> convertToVector(Handle<Value> val) {

        if (val->IsString()) {

            Nan::Utf8String strVal(val);
            return std::vector<char>(*strVal, (*strVal) + strVal.length());

        } else if (node::Buffer::HasInstance(val)) {

            char* valPtr = node::Buffer::Data(val);
            size_t valLen = node::Buffer::Length(val);

            return std::vector<char>(valPtr, valPtr + valLen);
        }

        Nan::ThrowTypeError("Value has got incorrect type. Should be Buffer or String.");

        return std::vector<char>();
    }

    static Nan::Persistent<Function> constructor;

    static NAN_METHOD(New) {

        if (info.Length() < 2) {
            Nan::ThrowError("Missing parameters. Algorithm and IV should be specified.");
            return info.GetReturnValue().Set(Nan::Undefined());
        }

        if (!Nan::New(AlgorithmBlock<algorithm::AlgorithmBlock>::functionTemplate)->HasInstance(info[0])) {
            Nan::ThrowTypeError("First parameter is not an block algorithm object");
            return info.GetReturnValue().Set(Nan::Undefined());
        }

        if (!info.IsConstructCall()) {
            Local<Value> argv[] = {info[0], info[1]};
            Local<Function> ctr = Nan::New<Function>(constructor);
            return info.GetReturnValue().Set(Nan::NewInstance(ctr, 2, argv).ToLocalChecked());
        }

        AlgorithmBlock<algorithm::AlgorithmBlock>* algorithm =
        node::ObjectWrap::Unwrap<AlgorithmBlock<algorithm::AlgorithmBlock>>(info[0]->ToObject());

        Mode<T>* container = new Mode<T>(algorithm->algorithm, convertToVector(info[1]));

        container->Wrap(info.This());

        return info.GetReturnValue().Set(info.This());
    }

    static NAN_METHOD(Transform) {

        if (info.Length() < 1) {
            Nan::ThrowError("Missing parameter. Data should be specified.");
            return info.GetReturnValue().Set(Nan::Undefined());
        }

        Mode<T>* container = ObjectWrap::Unwrap<Mode<T>>(info.This());


        std::vector<char> prev = convertToVector(info[0]);

        if (container->mode->isPaddingRequired() && !container->mode->isSizeValid(prev.size())) {
            Nan::ThrowError("Data size should be aligned to algorithm block size.");
            return info.GetReturnValue().Set(Nan::Undefined());
        }

        std::vector<char> data = container->mode->transform(prev);

        char* buffer = new char[data.size()];
        std::copy(data.begin(), data.end(), buffer);

        return info.GetReturnValue().Set(Nan::NewBuffer(buffer, data.size(), freeBuffer, 0).ToLocalChecked());
    }

    static NAN_METHOD(IsPaddingRequired) {

        Mode<T>* container = ObjectWrap::Unwrap<Mode<T>>(info.This());

        return info.GetReturnValue().Set(Nan::New<Boolean>(container->mode->isPaddingRequired()));
    }
    
    static NAN_METHOD(GetBlockSize) {

        Mode<T>* container = ObjectWrap::Unwrap<Mode<T>>(info.This());

        return info.GetReturnValue().Set(Nan::New<Number>(container->mode->getBlockSize()));
    }

public:

    static Handle<FunctionTemplate> getFunctionTemplate(std::string className, Local<FunctionTemplate> parent) {

        Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(New);
        tpl->SetClassName(Nan::New(className).ToLocalChecked());
        tpl->InstanceTemplate()->SetInternalFieldCount(1);
        tpl->Inherit(parent);

        Nan::SetPrototypeMethod(tpl, "transform", Transform);
        Nan::SetPrototypeMethod(tpl, "isPaddingRequired", IsPaddingRequired);
        Nan::SetPrototypeMethod(tpl, "getBlockSize", GetBlockSize);

        constructor.Reset(tpl->GetFunction());

        return tpl;
    }

};

};

#endif
