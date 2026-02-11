#include "pch.h"
#include "BuiltinObject.h"

void BuiltinObjects::registerAll(JSContext* ctx, JSValue global_obj) {
    // Core Objects
    GlobalObject::registerGlobalFunctions(ctx, global_obj);
    StringObject::registerStringFunctions(ctx, global_obj);
    ArrayObject::registerArrayFunctions(ctx, global_obj);
    MathObject::registerMathFunctions(ctx, global_obj);
    RegExpObject::registerRegExpMethods(ctx, global_obj);

    // DOM & Browser APIs
    ConsoleObject::registerConsoleObject(ctx, global_obj);
    DocumentObject::registerDocumentObject(ctx, global_obj);
    WindowObject::registerWindowObject(ctx, global_obj);
    LocalStorageObject::registerLocalStorageObject(ctx, global_obj);

    // Web APIs
    FormDataObject::registerFormDataObject(ctx, global_obj);
    BlobObject::registerBlobObject(ctx, global_obj);
    TextDecoderObject::registerTextDecoder(ctx, global_obj);
    WebSocketObject::registerWebSocketObject(ctx, global_obj);
    WebAssemblyObject::registerWebAssemblyObject(ctx, global_obj);
    WorkerObject::registerWorkerObject(ctx, global_obj);

    // Third-party & Extensions
    JQueryObject::registerJQueryObject(ctx, global_obj);
    MediumPriorityAPIs::registerMediumPriorityAPIs(ctx, global_obj);
    LowPriorityAPIs::registerLowPriorityAPIs(ctx, global_obj);
}