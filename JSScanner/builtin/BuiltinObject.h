#pragma once

#include "../../mon47-opensrc/opensrc/quickjs-ng/include/quickjs.h"
#include "helpers/Base64Utils.h"
#include "helpers/SensitiveKeywordDetector.h"
#include "helpers/JSValueConverter.h"
#include "helpers/MockHelpers.h"
#include "objects/GlobalObject.h"
#include "objects/StringObject.h"
#include "objects/ArrayObject.h"
#include "objects/ConsoleObject.h"
#include "objects/LocalStorageObject.h"
#include "objects/ElementObject.h"
#include "objects/DocumentObject.h"
#include "objects/WindowObject.h"
#include "objects/MathObject.h"
#include "objects/JQueryObject.h"
#include "objects/TextDecoderObject.h"
#include "objects/FormDataObject.h"
#include "objects/RegExpObject.h"
#include "objects/IndexedDBObject.h"
#include "objects/WebAssemblyObject.h"
#include "objects/WebSocketObject.h"
#include "objects/WorkerObject.h"
#include "objects/MediumPriorityAPIs.h"
#include "objects/LowPriorityAPIs.h"
#include "objects/BlobObject.h"
#include "objects/ActiveXObject.h"
#include "objects/ProxyFallbackObject.h"

// ✅ 통합 등록 클래스
class BuiltinObjects {
public:
    // 모든 빌트인 객체를 한 번에 등록
    static void registerAll(JSContext* ctx, JSValue global_obj);
};