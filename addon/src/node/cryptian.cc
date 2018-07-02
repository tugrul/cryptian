
#include "cryptian.h"

#define EXPORT_ALGORITHM_BLOCK(name) algorithm->Set(Nan::New(#name).ToLocalChecked(), \
    cryptian::AlgorithmBlock<cryptian::algorithm::name>::getFunctionTemplate(#name, algorithmBlock)->GetFunction());

#define EXPORT_ALGORITHM_STREAM(name) algorithm->Set(Nan::New(#name).ToLocalChecked(), \
    cryptian::AlgorithmStream<cryptian::algorithm::name>::getFunctionTemplate(#name, algorithmStream)->GetFunction());

#define EXPORT_MODE(name) v8::Local<v8::Object> name = Nan::New<v8::Object>();\
    name->Set(Nan::New("Cipher").ToLocalChecked(), \
    cryptian::Mode<cryptian::mode::name::Cipher>::getFunctionTemplate("Cipher")->GetFunction()); \
    name->Set(Nan::New("Decipher").ToLocalChecked(), \
    cryptian::Mode<cryptian::mode::name::Decipher>::getFunctionTemplate("Decipher")->GetFunction()); \
    mode->Set(Nan::New(#name).ToLocalChecked(), name);

template <typename T>
Nan::Persistent<FunctionTemplate> cryptian::AlgorithmBase<T>::functionTemplate;

template <typename T>
Nan::Persistent<Function> cryptian::AlgorithmBase<T>::constructor;

template <typename T>
Nan::Persistent<Function> cryptian::Mode<T>::constructor;


static void Init(v8::Handle<v8::Object> exports) {
    Nan::HandleScope scope;

    v8::Local<v8::Object> algorithm = Nan::New<v8::Object>();
    v8::Local<v8::Object> mode = Nan::New<v8::Object>();

    v8::Local<v8::FunctionTemplate> algorithmBlock =
        cryptian::AlgorithmBase<cryptian::algorithm::AlgorithmBlock>::getFunctionTemplate("AlgorithmBlock");


    v8::Local<v8::FunctionTemplate> algorithmStream =
        cryptian::AlgorithmBase<cryptian::algorithm::AlgorithmStream>::getFunctionTemplate("AlgorithmStream");


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
    EXPORT_MODE(cfb)
    EXPORT_MODE(ctr)
    EXPORT_MODE(ecb)
    EXPORT_MODE(ncfb)
    EXPORT_MODE(nofb)
    EXPORT_MODE(ofb)


    exports->Set(Nan::New("algorithm").ToLocalChecked(), algorithm);
    exports->Set(Nan::New("mode").ToLocalChecked(), mode);

    exports->Set(Nan::New("AlgorithmBlock").ToLocalChecked(), algorithmBlock->GetFunction());
    exports->Set(Nan::New("AlgorithmStream").ToLocalChecked(), algorithmStream->GetFunction());
}

NODE_MODULE(cryptian, Init)

