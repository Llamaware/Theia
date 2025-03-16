#include <fstream>
#include <iostream>
#include <string>

// The macro definitions for your intrinsics.
#define INTRINSICS_LIST(V)                                            \
  V(AsyncGeneratorReject, async_generator_reject, 2)                  \
  V(AsyncGeneratorResolve, async_generator_resolve, 3)                \
  V(AsyncGeneratorYield, async_generator_yield, 3)                    \
  V(CreateJSGeneratorObject, create_js_generator_object, 2)           \
  V(GeneratorGetContext, generator_get_context, 1)                    \
  V(GeneratorGetResumeMode, generator_get_resume_mode, 1)             \
  V(GeneratorGetInputOrDebugPos, generator_get_input_or_debug_pos, 1) \
  V(GeneratorClose, generator_close, 1)                               \
  V(GetImportMetaObject, get_import_meta_object, 0)                   \
  V(Call, call, -1)                                                   \
  V(ClassOf, class_of, 1)                                             \
  V(CreateIterResultObject, create_iter_result_object, 2)             \
  V(CreateAsyncFromSyncIterator, create_async_from_sync_iterator, 1)  \
  V(HasProperty, has_property, 2)                                     \
  V(IsArray, is_array, 1)                                             \
  V(IsJSMap, is_js_map, 1)                                            \
  V(IsJSProxy, is_js_proxy, 1)                                        \
  V(IsJSReceiver, is_js_receiver, 1)                                  \
  V(IsJSSet, is_js_set, 1)                                            \
  V(IsJSWeakMap, is_js_weak_map, 1)                                   \
  V(IsJSWeakSet, is_js_weak_set, 1)                                   \
  V(IsSmi, is_smi, 1)                                                 \
  V(IsTypedArray, is_typed_array, 1)                                  \
  V(ToString, to_string, 1)                                           \
  V(ToLength, to_length, 1)                                           \
  V(ToInteger, to_integer, 1)                                         \
//  V(ToNumber, to_number, 1)                                           \
//  V(ToObject, to_object, 1)

// Macro helper: prints a line in the required format.
#define PRINT_INTRINSIC(Upper, lower, nargs) \
  out << "_" #Upper << ":" << nargs << std::endl;

int main() {
    std::ofstream out("new_interpreter_intrinsics.txt");
    if (!out) {
        std::cerr << "Error opening file" << std::endl;
        return 1;
    }
    INTRINSICS_LIST(PRINT_INTRINSIC)
    out.close();
	return 0;
}
