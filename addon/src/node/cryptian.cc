
#include "cryptian.h"

#define EXPORT_ALGORITHM_BLOCK(name) Nan::Set(algorithm, Nan::New(#name).ToLocalChecked(), \
    Nan::GetFunction(cryptian::AlgorithmBlock<cryptian::algorithm::name>::getFunctionTemplate(#name, algorithmBlock)).ToLocalChecked());

#define EXPORT_ALGORITHM_STREAM(name) Nan::Set(algorithm, Nan::New(#name).ToLocalChecked(), \
    Nan::GetFunction(cryptian::AlgorithmStream<cryptian::algorithm::name>::getFunctionTemplate(#name, algorithmStream)).ToLocalChecked());

#define EXPORT_MODE(name) v8::Local<v8::Object> name = Nan::New<v8::Object>();\
    Nan::Set(name, Nan::New("Cipher").ToLocalChecked(), \
    Nan::GetFunction(cryptian::Mode<cryptian::mode::name::Cipher>::getFunctionTemplate("Cipher", modeBase)).ToLocalChecked()); \
    Nan::Set(name, Nan::New("Decipher").ToLocalChecked(), \
    Nan::GetFunction(cryptian::Mode<cryptian::mode::name::Decipher>::getFunctionTemplate("Decipher", modeBase)).ToLocalChecked()); \
    Nan::Set(mode, Nan::New(#name).ToLocalChecked(), name);

template <typename T>
Nan::Persistent<FunctionTemplate> cryptian::AlgorithmBase<T>::functionTemplate;

template <typename T>
Nan::Persistent<Function> cryptian::AlgorithmBase<T>::constructor;

template <typename T>
Nan::Persistent<Function> cryptian::Mode<T>::constructor;


Nan::Persistent<Function> cryptian::ModeBase::constructor;


NAN_MODULE_INIT(Init) {
    Nan::HandleScope scope;

    v8::Local<v8::Object> algorithm = Nan::New<v8::Object>();
    v8::Local<v8::Object> mode = Nan::New<v8::Object>();

    v8::Local<v8::FunctionTemplate> algorithmBlock =
        cryptian::AlgorithmBase<cryptian::algorithm::AlgorithmBlock>::getFunctionTemplate("AlgorithmBlock");


    v8::Local<v8::FunctionTemplate> algorithmStream =
        cryptian::AlgorithmBase<cryptian::algorithm::AlgorithmStream>::getFunctionTemplate("AlgorithmStream");

    v8::Local<v8::FunctionTemplate> modeBase =
        cryptian::ModeBase::getFunctionTemplate();
        

    EXPORT_ALGORITHM_BLOCK(Blowfish)
    EXPORT_ALGORITHM_BLOCK(Cast128)
    EXPORT_ALGORITHM_BLOCK(Cast256)
    EXPORT_ALGORITHM_BLOCK(Des)
    EXPORT_ALGORITHM_BLOCK(Threeway)
    EXPORT_ALGORITHM_BLOCK(Gost)
    EXPORT_ALGORITHM_BLOCK(Loki97)
    EXPORT_ALGORITHM_BLOCK(Rc2)
    EXPORT_ALGORITHM_BLOCK(Rijndael128)
    EXPORT_ALGORITHM_BLOCK(Rijndael192)
    EXPORT_ALGORITHM_BLOCK(Rijndael256)
    EXPORT_ALGORITHM_BLOCK(Safer)
    EXPORT_ALGORITHM_BLOCK(Saferplus)
    EXPORT_ALGORITHM_BLOCK(Tripledes)
    EXPORT_ALGORITHM_BLOCK(Xtea)
    EXPORT_ALGORITHM_BLOCK(Dummy)

    EXPORT_ALGORITHM_STREAM(Arcfour)
    EXPORT_ALGORITHM_STREAM(Enigma)
    EXPORT_ALGORITHM_STREAM(Wake)

    EXPORT_MODE(cbc)
    EXPORT_MODE(pcbc)
    EXPORT_MODE(cfb)
    EXPORT_MODE(ctr)
    EXPORT_MODE(ecb)
    EXPORT_MODE(ncfb)
    EXPORT_MODE(nofb)
    EXPORT_MODE(ofb)


    Nan::Set(target, Nan::New("algorithm").ToLocalChecked(), algorithm);
    Nan::Set(target, Nan::New("mode").ToLocalChecked(), mode);

    Nan::Set(target, Nan::New("AlgorithmBlock").ToLocalChecked(), Nan::GetFunction(algorithmBlock).ToLocalChecked());
    Nan::Set(target, Nan::New("AlgorithmStream").ToLocalChecked(), Nan::GetFunction(algorithmStream).ToLocalChecked());
    
    Nan::Set(target, Nan::New("Mode").ToLocalChecked(), Nan::GetFunction(modeBase).ToLocalChecked());
}

NODE_MODULE(cryptian, Init)

