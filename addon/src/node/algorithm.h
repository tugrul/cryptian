
#ifndef CRYPTIAN_ADDON_ALGORITM_H_
#define CRYPTIAN_ADDON_ALGORITM_H_

#include <nan.h>

using namespace v8;

namespace cryptian {

template <typename T>
class AlgorithmBase : public node::ObjectWrap {
public:
    static Local<FunctionTemplate> getFunctionTemplate(std::string functionName) {

        Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(Forbidden);
        tpl->SetClassName(Nan::New(functionName).ToLocalChecked());

        functionTemplate.Reset(tpl);
        constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());

        return tpl;
    }
protected:
    static Nan::Persistent<Function> constructor;
    static Nan::Persistent<FunctionTemplate> functionTemplate;

    AlgorithmBase() {
        algorithm = new T();
    }
    
    ~AlgorithmBase() {
        delete algorithm;
    }

    T* algorithm;

    static void freeBuffer(char *buffer, void *hint) {
        delete[] buffer;
    }

    // Returns false and schedules a TypeError when the value cannot be
    // converted. Throwing does not unwind C++, so callers must check the
    // result and return rather than carrying on with an empty vector.
    static bool convertToVector(Local<Value> val, std::vector<char>& out) {

        if (val->IsString()) {

            Nan::Utf8String strVal(val);
            out.assign(*strVal, (*strVal) + strVal.length());

            return true;
        }

        if (node::Buffer::HasInstance(val)) {

            char* valPtr = node::Buffer::Data(val);
            size_t valLen = node::Buffer::Length(val);

            out.assign(valPtr, valPtr + valLen);

            return true;
        }

        Nan::ThrowTypeError("Value has got incorrect type. Should be Buffer or String.");

        return false;
    }

    static NAN_METHOD(Forbidden) {
        Nan::ThrowTypeError("Invalid usage. This method is abstract.");
        return info.GetReturnValue().Set(Nan::Undefined());
    }

    static NAN_METHOD(GetName) {

        AlgorithmBase<T>* container = node::ObjectWrap::Unwrap<AlgorithmBase<T>>(info.This());

        return info.GetReturnValue().Set(Nan::New<String>(container->algorithm->getName()).ToLocalChecked());
    }

    static NAN_METHOD(GetVersion) {

        AlgorithmBase<T>* container = node::ObjectWrap::Unwrap<AlgorithmBase<T>>(info.This());

        return info.GetReturnValue().Set(Nan::New<Number>(container->algorithm->getVersion()));
    }

    static NAN_METHOD(GetKeySizes) {

        AlgorithmBase<T>* container = node::ObjectWrap::Unwrap<AlgorithmBase<T>>(info.This());

        std::vector<size_t> keySizes = container->algorithm->getKeySizes();

        Local<Array> array = Nan::New<Array>(keySizes.size());

        for (size_t i = 0; i < keySizes.size(); i++) {
            Nan::Set(array, i, Nan::New<Number>(keySizes[i]));
        }

        return info.GetReturnValue().Set(array);
    }

    static NAN_METHOD(SetKey) {

        if (info.Length() < 1) {
            Nan::ThrowTypeError("Missing parameter. Key should be specified.");
            return info.GetReturnValue().Set(Nan::Undefined());
        }

        std::vector<char> key;

        if (!AlgorithmBase<T>::convertToVector(info[0], key)) {
            return info.GetReturnValue().Set(Nan::Undefined());
        }

        AlgorithmBase<T>* container = ObjectWrap::Unwrap<AlgorithmBase<T>>(info.This());

        container->algorithm->setKey(key);

        return info.GetReturnValue().Set(info.This());
    }

    static NAN_METHOD(Reset) {

        AlgorithmBase<T>* container = ObjectWrap::Unwrap<AlgorithmBase<T>>(info.This());

        container->algorithm->reset();

        return info.GetReturnValue().Set(info.This());
    }

    static NAN_METHOD(Encrypt) {

        if (info.Length() < 1) {
            Nan::ThrowTypeError("Missing parameter. Plaintext should be specified.");
            return info.GetReturnValue().Set(Nan::Undefined());
        }

        std::vector<char> input;

        if (!AlgorithmBase<T>::convertToVector(info[0], input)) {
            return info.GetReturnValue().Set(Nan::Undefined());
        }

        AlgorithmBase<T>* container = ObjectWrap::Unwrap<AlgorithmBase<T>>(info.This());

        std::vector<char> ciphertext = container->algorithm->encrypt(input);

        char* buffer = new char[ciphertext.size()];

        std::copy(ciphertext.begin(), ciphertext.end(), buffer);

        return info.GetReturnValue().Set(Nan::NewBuffer(buffer, ciphertext.size(), freeBuffer, 0).ToLocalChecked());
    }

    static NAN_METHOD(Decrypt) {

        if (info.Length() < 1) {
            Nan::ThrowTypeError("Missing parameter. Ciphertext should be specified.");
            return info.GetReturnValue().Set(Nan::Undefined());
        }

        std::vector<char> input;

        if (!AlgorithmBase<T>::convertToVector(info[0], input)) {
            return info.GetReturnValue().Set(Nan::Undefined());
        }

        AlgorithmBase<T>* container = ObjectWrap::Unwrap<AlgorithmBase<T>>(info.This());

        std::vector<char> plaintext = container->algorithm->decrypt(input);

        char* buffer = new char[plaintext.size()];

        std::copy(plaintext.begin(), plaintext.end(), buffer);

        return info.GetReturnValue().Set(Nan::NewBuffer(buffer, plaintext.size(), freeBuffer, 0).ToLocalChecked());
    }

    static NAN_METHOD(SetEndianCompat) {
        if (info.Length() < 1) {
            Nan::ThrowTypeError("Missing parameter. Set true to active compatibility mode.");
            return info.GetReturnValue().Set(Nan::Undefined());
        }

        AlgorithmBase<T>* container = ObjectWrap::Unwrap<AlgorithmBase<T>>(info.This());

        container->algorithm->setEndianCompat(Nan::Equals(info[0], Nan::True()).FromJust());

        return info.GetReturnValue().Set(info.This());
    }
};

template <typename T>
class AlgorithmBlock : public AlgorithmBase<T> {
    template<typename K>
    friend class Mode;
public:

    static Local<FunctionTemplate> getFunctionTemplate(std::string functionName, Local<FunctionTemplate> parent) {

        Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(New);
        tpl->SetClassName(Nan::New(functionName).ToLocalChecked());
        tpl->InstanceTemplate()->SetInternalFieldCount(1);
        tpl->Inherit(parent);

        Nan::SetPrototypeMethod(tpl, "setKey", AlgorithmBase<T>::SetKey);

        Nan::SetPrototypeMethod(tpl, "encrypt", AlgorithmBase<T>::Encrypt);
        Nan::SetPrototypeMethod(tpl, "decrypt", AlgorithmBase<T>::Decrypt);

        Nan::SetPrototypeMethod(tpl, "getName", AlgorithmBase<T>::GetName);
        Nan::SetPrototypeMethod(tpl, "getVersion", AlgorithmBase<T>::GetVersion);
        Nan::SetPrototypeMethod(tpl, "getKeySizes", AlgorithmBase<T>::GetKeySizes);

        Nan::SetPrototypeMethod(tpl, "reset", AlgorithmBase<T>::Reset);
        Nan::SetPrototypeMethod(tpl, "setEndianCompat", AlgorithmBase<T>::SetEndianCompat);

        Nan::SetPrototypeMethod(tpl, "getBlockSize", GetBlockSize);

        AlgorithmBase<T>::functionTemplate.Reset(tpl);
        AlgorithmBase<T>::constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());

        return tpl;
    }

protected:

    static NAN_METHOD(New) {

        if (!info.IsConstructCall()) {
            Local<Function> ctr = Nan::New<Function>(AlgorithmBase<T>::constructor);
            return info.GetReturnValue().Set(Nan::NewInstance(ctr).ToLocalChecked());
        }

        AlgorithmBlock<T>* container = new AlgorithmBlock<T>();

        container->Wrap(info.This());

        return info.GetReturnValue().Set(info.This());
    }


    static NAN_METHOD(GetBlockSize) {

        AlgorithmBlock<T>* container = node::ObjectWrap::Unwrap<AlgorithmBlock<T>>(info.This());

        return info.GetReturnValue().Set(Nan::New<Number>(container->algorithm->getBlockSize()));
    }


};

template <typename T>
class AlgorithmStream : public AlgorithmBase<T> {
public:

    static Local<FunctionTemplate> getFunctionTemplate(std::string functionName, Local<FunctionTemplate> parent) {

        Local<FunctionTemplate> tpl = Nan::New<FunctionTemplate>(New);
        tpl->SetClassName(Nan::New(functionName).ToLocalChecked());
        tpl->InstanceTemplate()->SetInternalFieldCount(1);
        tpl->Inherit(parent);

        Nan::SetPrototypeMethod(tpl, "setKey", AlgorithmBase<T>::SetKey);
        Nan::SetPrototypeMethod(tpl, "setIv", SetIv);

        Nan::SetPrototypeMethod(tpl, "encrypt", AlgorithmBase<T>::Encrypt);
        Nan::SetPrototypeMethod(tpl, "decrypt", AlgorithmBase<T>::Decrypt);

        Nan::SetPrototypeMethod(tpl, "getName", AlgorithmBase<T>::GetName);
        Nan::SetPrototypeMethod(tpl, "getVersion", AlgorithmBase<T>::GetVersion);
        Nan::SetPrototypeMethod(tpl, "getKeySizes", AlgorithmBase<T>::GetKeySizes);

        Nan::SetPrototypeMethod(tpl, "reset", AlgorithmBase<T>::Reset);

        Nan::SetPrototypeMethod(tpl, "getIvSize", GetIvSize);

        AlgorithmBase<T>::functionTemplate.Reset(tpl);
        AlgorithmBase<T>::constructor.Reset(Nan::GetFunction(tpl).ToLocalChecked());

        return tpl;
    }


protected:

    static NAN_METHOD(New) {

        if (!info.IsConstructCall()) {
            Local<Function> ctr = Nan::New<Function>(AlgorithmBase<T>::constructor);
            return info.GetReturnValue().Set(Nan::NewInstance(ctr).ToLocalChecked());
        }

        AlgorithmStream<T>* container = new AlgorithmStream<T>();

        container->Wrap(info.This());

        return info.GetReturnValue().Set(info.This());
    }

    static NAN_METHOD(SetIv) {

        if (info.Length() < 1) {
            Nan::ThrowTypeError("Missing parameter. Iv should be specified.");
            return info.GetReturnValue().Set(Nan::Undefined());
        }

        std::vector<char> iv;

        if (!AlgorithmBase<T>::convertToVector(info[0], iv)) {
            return info.GetReturnValue().Set(Nan::Undefined());
        }

        AlgorithmStream<T>* container = node::ObjectWrap::Unwrap<AlgorithmStream<T>>(info.This());

        container->algorithm->setIv(iv);

        return info.GetReturnValue().Set(info.This());
    }

    static NAN_METHOD(GetIvSize) {

        AlgorithmStream<T>* container = node::ObjectWrap::Unwrap<AlgorithmStream<T>>(info.This());

        return info.GetReturnValue().Set(Nan::New<Number>(container->algorithm->getIvSize()));
    }
};

};

#endif
