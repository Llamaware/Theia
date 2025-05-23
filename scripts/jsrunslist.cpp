#include <iostream>
#include <fstream>
#include <string>

#define NATIVE_CONTEXT_INTRINSIC_FUNCTIONS(V)                               \
  V(ASYNC_FUNCTION_AWAIT_CAUGHT_INDEX, JSFunction,                          \
    async_function_await_caught)                                            \
  V(ASYNC_FUNCTION_AWAIT_UNCAUGHT_INDEX, JSFunction,                        \
    async_function_await_uncaught)                                          \
  V(ASYNC_FUNCTION_PROMISE_CREATE_INDEX, JSFunction,                        \
    async_function_promise_create)                                          \
  V(ASYNC_FUNCTION_PROMISE_RELEASE_INDEX, JSFunction,                       \
    async_function_promise_release)                                         \
  V(IS_ARRAYLIKE, JSFunction, is_arraylike)                                 \
  V(GENERATOR_NEXT_INTERNAL, JSFunction, generator_next_internal)           \
  V(MAKE_ERROR_INDEX, JSFunction, make_error)                               \
  V(MAKE_RANGE_ERROR_INDEX, JSFunction, make_range_error)                   \
  V(MAKE_SYNTAX_ERROR_INDEX, JSFunction, make_syntax_error)                 \
  V(MAKE_TYPE_ERROR_INDEX, JSFunction, make_type_error)                     \
  V(MAKE_URI_ERROR_INDEX, JSFunction, make_uri_error)                       \
  V(OBJECT_CREATE, JSFunction, object_create)                               \
  V(OBJECT_DEFINE_PROPERTIES, JSFunction, object_define_properties)         \
  V(OBJECT_DEFINE_PROPERTY, JSFunction, object_define_property)             \
  V(OBJECT_GET_PROTOTYPE_OF, JSFunction, object_get_prototype_of)           \
  V(OBJECT_IS_EXTENSIBLE, JSFunction, object_is_extensible)                 \
  V(OBJECT_IS_FROZEN, JSFunction, object_is_frozen)                         \
  V(OBJECT_IS_SEALED, JSFunction, object_is_sealed)                         \
  V(OBJECT_KEYS, JSFunction, object_keys)                                   \
  V(REGEXP_INTERNAL_MATCH, JSFunction, regexp_internal_match)               \
  V(REFLECT_APPLY_INDEX, JSFunction, reflect_apply)                         \
  V(REFLECT_CONSTRUCT_INDEX, JSFunction, reflect_construct)                 \
  V(REFLECT_DEFINE_PROPERTY_INDEX, JSFunction, reflect_define_property)     \
  V(REFLECT_DELETE_PROPERTY_INDEX, JSFunction, reflect_delete_property)     \
  V(SPREAD_ARGUMENTS_INDEX, JSFunction, spread_arguments)                   \
  V(SPREAD_ITERABLE_INDEX, JSFunction, spread_iterable)                     \
  V(TYPED_ARRAY_CONSTRUCT_BY_ARRAY_BUFFER_INDEX, JSFunction,                \
    typed_array_construct_by_array_buffer)                                  \
  V(TYPED_ARRAY_CONSTRUCT_BY_ARRAY_LIKE_INDEX, JSFunction,                  \
    typed_array_construct_by_array_like)                                    \
  V(TYPED_ARRAY_CONSTRUCT_BY_LENGTH_INDEX, JSFunction,                      \
    typed_array_construct_by_length)                                        \
  V(MATH_FLOOR_INDEX, JSFunction, math_floor)                               \
  V(MATH_POW_INDEX, JSFunction, math_pow)                                   \
  V(NEW_PROMISE_CAPABILITY_INDEX, JSFunction, new_promise_capability)       \
  V(PROMISE_INTERNAL_CONSTRUCTOR_INDEX, JSFunction,                         \
    promise_internal_constructor)                                           \
  V(PROMISE_INTERNAL_REJECT_INDEX, JSFunction, promise_internal_reject)     \
  V(IS_PROMISE_INDEX, JSFunction, is_promise)                               \
  V(PROMISE_RESOLVE_INDEX, JSFunction, promise_resolve)                     \
  V(PROMISE_THEN_INDEX, JSFunction, promise_then)                           \
  V(PROMISE_HANDLE_INDEX, JSFunction, promise_handle)                       \
  V(PROMISE_HANDLE_REJECT_INDEX, JSFunction, promise_handle_reject)         \
  V(ASYNC_GENERATOR_AWAIT_CAUGHT, JSFunction, async_generator_await_caught) \
  V(ASYNC_GENERATOR_AWAIT_UNCAUGHT, JSFunction, async_generator_await_uncaught)

#define NATIVE_CONTEXT_IMPORTED_FIELDS(V)                                 \
  V(ARRAY_CONCAT_INDEX, JSFunction, array_concat)                         \
  V(ARRAY_POP_INDEX, JSFunction, array_pop)                               \
  V(ARRAY_PUSH_INDEX, JSFunction, array_push)                             \
  V(ARRAY_SHIFT_INDEX, JSFunction, array_shift)                           \
  V(ARRAY_SPLICE_INDEX, JSFunction, array_splice)                         \
  V(ARRAY_SLICE_INDEX, JSFunction, array_slice)                           \
  V(ARRAY_UNSHIFT_INDEX, JSFunction, array_unshift)                       \
  V(ARRAY_ENTRIES_ITERATOR_INDEX, JSFunction, array_entries_iterator)     \
  V(ARRAY_FOR_EACH_ITERATOR_INDEX, JSFunction, array_for_each_iterator)   \
  V(ARRAY_KEYS_ITERATOR_INDEX, JSFunction, array_keys_iterator)           \
  V(ARRAY_VALUES_ITERATOR_INDEX, JSFunction, array_values_iterator)       \
  V(DERIVED_GET_TRAP_INDEX, JSFunction, derived_get_trap)                 \
  V(ERROR_FUNCTION_INDEX, JSFunction, error_function)                     \
  V(ERROR_TO_STRING, JSFunction, error_to_string)                         \
  V(EVAL_ERROR_FUNCTION_INDEX, JSFunction, eval_error_function)           \
  V(GLOBAL_EVAL_FUN_INDEX, JSFunction, global_eval_fun)                   \
  V(GLOBAL_PROXY_FUNCTION_INDEX, JSFunction, global_proxy_function)       \
  V(MAP_DELETE_INDEX, JSFunction, map_delete)                             \
  V(MAP_GET_INDEX, JSFunction, map_get)                                   \
  V(MAP_HAS_INDEX, JSFunction, map_has)                                   \
  V(MAP_SET_INDEX, JSFunction, map_set)                                   \
  V(FUNCTION_HAS_INSTANCE_INDEX, JSFunction, function_has_instance)       \
  V(OBJECT_VALUE_OF, JSFunction, object_value_of)                         \
  V(OBJECT_TO_STRING, JSFunction, object_to_string)                       \
  V(PROMISE_CATCH_INDEX, JSFunction, promise_catch)                       \
  V(PROMISE_FUNCTION_INDEX, JSFunction, promise_function)                 \
  V(RANGE_ERROR_FUNCTION_INDEX, JSFunction, range_error_function)         \
  V(REFERENCE_ERROR_FUNCTION_INDEX, JSFunction, reference_error_function) \
  V(SET_ADD_INDEX, JSFunction, set_add)                                   \
  V(SET_DELETE_INDEX, JSFunction, set_delete)                             \
  V(SET_HAS_INDEX, JSFunction, set_has)                                   \
  V(SYNTAX_ERROR_FUNCTION_INDEX, JSFunction, syntax_error_function)       \
  V(TYPE_ERROR_FUNCTION_INDEX, JSFunction, type_error_function)           \
  V(URI_ERROR_FUNCTION_INDEX, JSFunction, uri_error_function)             \
  V(WASM_COMPILE_ERROR_FUNCTION_INDEX, JSFunction,                        \
    wasm_compile_error_function)                                          \
  V(WASM_LINK_ERROR_FUNCTION_INDEX, JSFunction, wasm_link_error_function) \
  V(WASM_RUNTIME_ERROR_FUNCTION_INDEX, JSFunction, wasm_runtime_error_function)

#define NATIVE_CONTEXT_JS_ARRAY_ITERATOR_MAPS(V)                               \
  V(TYPED_ARRAY_KEY_ITERATOR_MAP_INDEX, Map, typed_array_key_iterator_map)     \
  V(FAST_ARRAY_KEY_ITERATOR_MAP_INDEX, Map, fast_array_key_iterator_map)       \
  V(GENERIC_ARRAY_KEY_ITERATOR_MAP_INDEX, Map, array_key_iterator_map)         \
                                                                               \
  V(UINT8_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                             \
    uint8_array_key_value_iterator_map)                                        \
  V(INT8_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                              \
    int8_array_key_value_iterator_map)                                         \
  V(UINT16_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                            \
    uint16_array_key_value_iterator_map)                                       \
  V(INT16_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                             \
    int16_array_key_value_iterator_map)                                        \
  V(UINT32_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                            \
    uint32_array_key_value_iterator_map)                                       \
  V(INT32_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                             \
    int32_array_key_value_iterator_map)                                        \
  V(FLOAT32_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                           \
    float32_array_key_value_iterator_map)                                      \
  V(FLOAT64_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                           \
    float64_array_key_value_iterator_map)                                      \
  V(UINT8_CLAMPED_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                     \
    uint8_clamped_array_key_value_iterator_map)                                \
                                                                               \
  V(FAST_SMI_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                          \
    fast_smi_array_key_value_iterator_map)                                     \
  V(FAST_HOLEY_SMI_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                    \
    fast_holey_smi_array_key_value_iterator_map)                               \
  V(FAST_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                              \
    fast_array_key_value_iterator_map)                                         \
  V(FAST_HOLEY_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                        \
    fast_holey_array_key_value_iterator_map)                                   \
  V(FAST_DOUBLE_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                       \
    fast_double_array_key_value_iterator_map)                                  \
  V(FAST_HOLEY_DOUBLE_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                 \
    fast_holey_double_array_key_value_iterator_map)                            \
  V(GENERIC_ARRAY_KEY_VALUE_ITERATOR_MAP_INDEX, Map,                           \
    array_key_value_iterator_map)                                              \
                                                                               \
  V(UINT8_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map, uint8_array_value_iterator_map) \
  V(INT8_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map, int8_array_value_iterator_map)   \
  V(UINT16_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map,                                \
    uint16_array_value_iterator_map)                                           \
  V(INT16_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map, int16_array_value_iterator_map) \
  V(UINT32_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map,                                \
    uint32_array_value_iterator_map)                                           \
  V(INT32_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map, int32_array_value_iterator_map) \
  V(FLOAT32_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map,                               \
    float32_array_value_iterator_map)                                          \
  V(FLOAT64_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map,                               \
    float64_array_value_iterator_map)                                          \
  V(UINT8_CLAMPED_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map,                         \
    uint8_clamped_array_value_iterator_map)                                    \
                                                                               \
  V(FAST_SMI_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map,                              \
    fast_smi_array_value_iterator_map)                                         \
  V(FAST_HOLEY_SMI_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map,                        \
    fast_holey_smi_array_value_iterator_map)                                   \
  V(FAST_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map, fast_array_value_iterator_map)   \
  V(FAST_HOLEY_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map,                            \
    fast_holey_array_value_iterator_map)                                       \
  V(FAST_DOUBLE_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map,                           \
    fast_double_array_value_iterator_map)                                      \
  V(FAST_HOLEY_DOUBLE_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map,                     \
    fast_holey_double_array_value_iterator_map)                                \
  V(GENERIC_ARRAY_VALUE_ITERATOR_MAP_INDEX, Map, array_value_iterator_map)

#define NATIVE_CONTEXT_FIELDS(V)                                               \
  V(GLOBAL_PROXY_INDEX, JSObject, global_proxy_object)                         \
  V(EMBEDDER_DATA_INDEX, FixedArray, embedder_data)                            \
  /* Below is alpha-sorted */                                                  \
  V(ACCESSOR_PROPERTY_DESCRIPTOR_MAP_INDEX, Map,                               \
    accessor_property_descriptor_map)                                          \
  V(ALLOW_CODE_GEN_FROM_STRINGS_INDEX, Object, allow_code_gen_from_strings)    \
  V(ALLOW_WASM_EVAL_INDEX, Object, allow_wasm_eval)                            \
  V(ARRAY_BUFFER_FUN_INDEX, JSFunction, array_buffer_fun)                      \
  V(ARRAY_BUFFER_MAP_INDEX, Map, array_buffer_map)                             \
  V(ARRAY_BUFFER_NOINIT_FUN_INDEX, JSFunction, array_buffer_noinit_fun)        \
  V(ARRAY_FUNCTION_INDEX, JSFunction, array_function)                          \
  V(ASYNC_FROM_SYNC_ITERATOR_MAP_INDEX, Map, async_from_sync_iterator_map)     \
  V(ASYNC_FUNCTION_AWAIT_REJECT_SHARED_FUN, SharedFunctionInfo,                \
    async_function_await_reject_shared_fun)                                    \
  V(ASYNC_FUNCTION_AWAIT_RESOLVE_SHARED_FUN, SharedFunctionInfo,               \
    async_function_await_resolve_shared_fun)                                   \
  V(ASYNC_FUNCTION_FUNCTION_INDEX, JSFunction, async_function_constructor)     \
  V(ASYNC_GENERATOR_FUNCTION_FUNCTION_INDEX, JSFunction,                       \
    async_generator_function_function)                                         \
  V(ASYNC_ITERATOR_VALUE_UNWRAP_SHARED_FUN, SharedFunctionInfo,                \
    async_iterator_value_unwrap_shared_fun)                                    \
  V(ASYNC_GENERATOR_AWAIT_REJECT_SHARED_FUN, SharedFunctionInfo,               \
    async_generator_await_reject_shared_fun)                                   \
  V(ASYNC_GENERATOR_AWAIT_RESOLVE_SHARED_FUN, SharedFunctionInfo,              \
    async_generator_await_resolve_shared_fun)                                  \
  V(ASYNC_GENERATOR_YIELD_RESOLVE_SHARED_FUN, SharedFunctionInfo,              \
    async_generator_yield_resolve_shared_fun)                                  \
  V(ASYNC_GENERATOR_RETURN_RESOLVE_SHARED_FUN, SharedFunctionInfo,             \
    async_generator_return_resolve_shared_fun)                                 \
  V(ASYNC_GENERATOR_RETURN_CLOSED_RESOLVE_SHARED_FUN, SharedFunctionInfo,      \
    async_generator_return_closed_resolve_shared_fun)                          \
  V(ASYNC_GENERATOR_RETURN_CLOSED_REJECT_SHARED_FUN, SharedFunctionInfo,       \
    async_generator_return_closed_reject_shared_fun)                           \
  V(ATOMICS_OBJECT, JSObject, atomics_object)                                  \
  V(BIGINT_FUNCTION_INDEX, JSFunction, bigint_function)                        \
  V(BOOLEAN_FUNCTION_INDEX, JSFunction, boolean_function)                      \
  V(BOUND_FUNCTION_WITH_CONSTRUCTOR_MAP_INDEX, Map,                            \
    bound_function_with_constructor_map)                                       \
  V(BOUND_FUNCTION_WITHOUT_CONSTRUCTOR_MAP_INDEX, Map,                         \
    bound_function_without_constructor_map)                                    \
  V(CALL_AS_CONSTRUCTOR_DELEGATE_INDEX, JSFunction,                            \
    call_as_constructor_delegate)                                              \
  V(CALL_AS_FUNCTION_DELEGATE_INDEX, JSFunction, call_as_function_delegate)    \
  V(CALLSITE_FUNCTION_INDEX, JSFunction, callsite_function)                    \
  V(CONTEXT_EXTENSION_FUNCTION_INDEX, JSFunction, context_extension_function)  \
  V(DATA_PROPERTY_DESCRIPTOR_MAP_INDEX, Map, data_property_descriptor_map)     \
  V(DATA_VIEW_FUN_INDEX, JSFunction, data_view_fun)                            \
  V(DATE_FUNCTION_INDEX, JSFunction, date_function)                            \
  V(DEBUG_CONTEXT_ID_INDEX, Object, debug_context_id)                          \
  V(ERROR_MESSAGE_FOR_CODE_GEN_FROM_STRINGS_INDEX, Object,                     \
    error_message_for_code_gen_from_strings)                                   \
  V(ERRORS_THROWN_INDEX, Smi, errors_thrown)                                   \
  V(EXTRAS_EXPORTS_OBJECT_INDEX, JSObject, extras_binding_object)              \
  V(EXTRAS_UTILS_OBJECT_INDEX, Object, extras_utils_object)                    \
  V(FAST_ALIASED_ARGUMENTS_MAP_INDEX, Map, fast_aliased_arguments_map)         \
  V(FAST_TEMPLATE_INSTANTIATIONS_CACHE_INDEX, FixedArray,                      \
    fast_template_instantiations_cache)                                        \
  V(FLOAT32_ARRAY_FUN_INDEX, JSFunction, float32_array_fun)                    \
  V(FLOAT64_ARRAY_FUN_INDEX, JSFunction, float64_array_fun)                    \
  V(FUNCTION_FUNCTION_INDEX, JSFunction, function_function)                    \
  V(GENERATOR_FUNCTION_FUNCTION_INDEX, JSFunction,                             \
    generator_function_function)                                               \
  V(GENERATOR_OBJECT_PROTOTYPE_MAP_INDEX, Map, generator_object_prototype_map) \
  V(ASYNC_GENERATOR_OBJECT_PROTOTYPE_MAP_INDEX, Map,                           \
    async_generator_object_prototype_map)                                      \
  V(INITIAL_ARRAY_ITERATOR_PROTOTYPE_INDEX, JSObject,                          \
    initial_array_iterator_prototype)                                          \
  V(INITIAL_ARRAY_ITERATOR_PROTOTYPE_MAP_INDEX, Map,                           \
    initial_array_iterator_prototype_map)                                      \
  V(INITIAL_ARRAY_PROTOTYPE_INDEX, JSObject, initial_array_prototype)          \
  V(INITIAL_ERROR_PROTOTYPE_INDEX, JSObject, initial_error_prototype)          \
  V(INITIAL_GENERATOR_PROTOTYPE_INDEX, JSObject, initial_generator_prototype)  \
  V(INITIAL_ASYNC_GENERATOR_PROTOTYPE_INDEX, JSObject,                         \
    initial_async_generator_prototype)                                         \
  V(INITIAL_ITERATOR_PROTOTYPE_INDEX, JSObject, initial_iterator_prototype)    \
  V(INITIAL_OBJECT_PROTOTYPE_INDEX, JSObject, initial_object_prototype)        \
  V(INITIAL_STRING_PROTOTYPE_INDEX, JSObject, initial_string_prototype)        \
  V(INT16_ARRAY_FUN_INDEX, JSFunction, int16_array_fun)                        \
  V(INT32_ARRAY_FUN_INDEX, JSFunction, int32_array_fun)                        \
  V(INT8_ARRAY_FUN_INDEX, JSFunction, int8_array_fun)                          \
  V(INTERNAL_ARRAY_FUNCTION_INDEX, JSFunction, internal_array_function)        \
  V(ITERATOR_RESULT_MAP_INDEX, Map, iterator_result_map)                       \
  V(INTL_DATE_TIME_FORMAT_FUNCTION_INDEX, JSFunction,                          \
    intl_date_time_format_function)                                            \
  V(INTL_NUMBER_FORMAT_FUNCTION_INDEX, JSFunction,                             \
    intl_number_format_function)                                               \
  V(INTL_COLLATOR_FUNCTION_INDEX, JSFunction, intl_collator_function)          \
  V(INTL_PLURAL_RULES_FUNCTION_INDEX, JSFunction, intl_plural_rules_function)  \
  V(INTL_V8_BREAK_ITERATOR_FUNCTION_INDEX, JSFunction,                         \
    intl_v8_break_iterator_function)                                           \
  V(JS_ARRAY_PACKED_SMI_ELEMENTS_MAP_INDEX, Map,                               \
    js_array_fast_smi_elements_map_index)                                      \
  V(JS_ARRAY_HOLEY_SMI_ELEMENTS_MAP_INDEX, Map,                                \
    js_array_fast_holey_smi_elements_map_index)                                \
  V(JS_ARRAY_PACKED_ELEMENTS_MAP_INDEX, Map, js_array_fast_elements_map_index) \
  V(JS_ARRAY_HOLEY_ELEMENTS_MAP_INDEX, Map,                                    \
    js_array_fast_holey_elements_map_index)                                    \
  V(JS_ARRAY_PACKED_DOUBLE_ELEMENTS_MAP_INDEX, Map,                            \
    js_array_fast_double_elements_map_index)                                   \
  V(JS_ARRAY_HOLEY_DOUBLE_ELEMENTS_MAP_INDEX, Map,                             \
    js_array_fast_holey_double_elements_map_index)                             \
  V(JS_MAP_FUN_INDEX, JSFunction, js_map_fun)                                  \
  V(JS_MAP_MAP_INDEX, Map, js_map_map)                                         \
  V(JS_MODULE_NAMESPACE_MAP, Map, js_module_namespace_map)                     \
  V(JS_SET_FUN_INDEX, JSFunction, js_set_fun)                                  \
  V(JS_SET_MAP_INDEX, Map, js_set_map)                                         \
  V(JS_WEAK_MAP_FUN_INDEX, JSFunction, js_weak_map_fun)                        \
  V(JS_WEAK_SET_FUN_INDEX, JSFunction, js_weak_set_fun)                        \
  V(MAP_CACHE_INDEX, Object, map_cache)                                        \
  V(MAP_KEY_ITERATOR_MAP_INDEX, Map, map_key_iterator_map)                     \
  V(MAP_KEY_VALUE_ITERATOR_MAP_INDEX, Map, map_key_value_iterator_map)         \
  V(MAP_VALUE_ITERATOR_MAP_INDEX, Map, map_value_iterator_map)                 \
  V(MATH_RANDOM_INDEX_INDEX, Smi, math_random_index)                           \
  V(MATH_RANDOM_CACHE_INDEX, Object, math_random_cache)                        \
  V(MESSAGE_LISTENERS_INDEX, TemplateList, message_listeners)                  \
  V(NATIVES_UTILS_OBJECT_INDEX, Object, natives_utils_object)                  \
  V(NORMALIZED_MAP_CACHE_INDEX, Object, normalized_map_cache)                  \
  V(NUMBER_FUNCTION_INDEX, JSFunction, number_function)                        \
  V(OBJECT_FUNCTION_INDEX, JSFunction, object_function)                        \
  V(OBJECT_FUNCTION_PROTOTYPE_MAP_INDEX, Map, object_function_prototype_map)   \
  V(OPAQUE_REFERENCE_FUNCTION_INDEX, JSFunction, opaque_reference_function)    \
  V(PROXY_CALLABLE_MAP_INDEX, Map, proxy_callable_map)                         \
  V(PROXY_CONSTRUCTOR_MAP_INDEX, Map, proxy_constructor_map)                   \
  V(PROXY_FUNCTION_INDEX, JSFunction, proxy_function)                          \
  V(PROXY_MAP_INDEX, Map, proxy_map)                                           \
  V(PROXY_REVOCABLE_RESULT_MAP_INDEX, Map, proxy_revocable_result_map)         \
  V(PROXY_REVOKE_SHARED_FUN, SharedFunctionInfo, proxy_revoke_shared_fun)      \
  V(PROMISE_GET_CAPABILITIES_EXECUTOR_SHARED_FUN, SharedFunctionInfo,          \
    promise_get_capabilities_executor_shared_fun)                              \
  V(PROMISE_RESOLVE_SHARED_FUN, SharedFunctionInfo,                            \
    promise_resolve_shared_fun)                                                \
  V(PROMISE_REJECT_SHARED_FUN, SharedFunctionInfo, promise_reject_shared_fun)  \
  V(PROMISE_THEN_FINALLY_SHARED_FUN, SharedFunctionInfo,                       \
    promise_then_finally_shared_fun)                                           \
  V(PROMISE_CATCH_FINALLY_SHARED_FUN, SharedFunctionInfo,                      \
    promise_catch_finally_shared_fun)                                          \
  V(PROMISE_VALUE_THUNK_FINALLY_SHARED_FUN, SharedFunctionInfo,                \
    promise_value_thunk_finally_shared_fun)                                    \
  V(PROMISE_THROWER_FINALLY_SHARED_FUN, SharedFunctionInfo,                    \
    promise_thrower_finally_shared_fun)                                        \
  V(PROMISE_ALL_RESOLVE_ELEMENT_SHARED_FUN, SharedFunctionInfo,                \
    promise_all_resolve_element_shared_fun)                                    \
  V(PROMISE_PROTOTYPE_MAP_INDEX, Map, promise_prototype_map)                   \
  V(REGEXP_EXEC_FUNCTION_INDEX, JSFunction, regexp_exec_function)              \
  V(REGEXP_FUNCTION_INDEX, JSFunction, regexp_function)                        \
  V(REGEXP_LAST_MATCH_INFO_INDEX, RegExpMatchInfo, regexp_last_match_info)     \
  V(REGEXP_INTERNAL_MATCH_INFO_INDEX, RegExpMatchInfo,                         \
    regexp_internal_match_info)                                                \
  V(REGEXP_PROTOTYPE_MAP_INDEX, Map, regexp_prototype_map)                     \
  V(REGEXP_RESULT_MAP_INDEX, Map, regexp_result_map)                           \
  V(SCRIPT_CONTEXT_TABLE_INDEX, ScriptContextTable, script_context_table)      \
  V(SCRIPT_FUNCTION_INDEX, JSFunction, script_function)                        \
  V(SECURITY_TOKEN_INDEX, Object, security_token)                              \
  V(SELF_WEAK_CELL_INDEX, WeakCell, self_weak_cell)                            \
  V(SERIALIZED_OBJECTS, FixedArray, serialized_objects)                        \
  V(SET_VALUE_ITERATOR_MAP_INDEX, Map, set_value_iterator_map)                 \
  V(SET_KEY_VALUE_ITERATOR_MAP_INDEX, Map, set_key_value_iterator_map)         \
  V(SHARED_ARRAY_BUFFER_FUN_INDEX, JSFunction, shared_array_buffer_fun)        \
  V(SLOPPY_ARGUMENTS_MAP_INDEX, Map, sloppy_arguments_map)                     \
  V(SLOW_ALIASED_ARGUMENTS_MAP_INDEX, Map, slow_aliased_arguments_map)         \
  V(STRICT_ARGUMENTS_MAP_INDEX, Map, strict_arguments_map)                     \
  V(SLOW_OBJECT_WITH_NULL_PROTOTYPE_MAP, Map,                                  \
    slow_object_with_null_prototype_map)                                       \
  V(SLOW_OBJECT_WITH_OBJECT_PROTOTYPE_MAP, Map,                                \
    slow_object_with_object_prototype_map)                                     \
  V(SLOW_TEMPLATE_INSTANTIATIONS_CACHE_INDEX, NumberDictionary,                \
    slow_template_instantiations_cache)                                        \
  /* All *_FUNCTION_MAP_INDEX definitions used by Context::FunctionMapIndex */ \
  /* must remain together. */                                                  \
  V(SLOPPY_FUNCTION_MAP_INDEX, Map, sloppy_function_map)                       \
  V(SLOPPY_FUNCTION_WITH_NAME_MAP_INDEX, Map, sloppy_function_with_name_map)   \
  V(SLOPPY_FUNCTION_WITHOUT_PROTOTYPE_MAP_INDEX, Map,                          \
    sloppy_function_without_prototype_map)                                     \
  V(SLOPPY_FUNCTION_WITH_READONLY_PROTOTYPE_MAP_INDEX, Map,                    \
    sloppy_function_with_readonly_prototype_map)                               \
  V(STRICT_FUNCTION_MAP_INDEX, Map, strict_function_map)                       \
  V(STRICT_FUNCTION_WITH_NAME_MAP_INDEX, Map, strict_function_with_name_map)   \
  V(STRICT_FUNCTION_WITH_READONLY_PROTOTYPE_MAP_INDEX, Map,                    \
    strict_function_with_readonly_prototype_map)                               \
  V(STRICT_FUNCTION_WITHOUT_PROTOTYPE_MAP_INDEX, Map,                          \
    strict_function_without_prototype_map)                                     \
  V(METHOD_WITH_NAME_MAP_INDEX, Map, method_with_name_map)                     \
  V(METHOD_WITH_HOME_OBJECT_MAP_INDEX, Map, method_with_home_object_map)       \
  V(METHOD_WITH_NAME_AND_HOME_OBJECT_MAP_INDEX, Map,                           \
    method_with_name_and_home_object_map)                                      \
  V(ASYNC_FUNCTION_MAP_INDEX, Map, async_function_map)                         \
  V(ASYNC_FUNCTION_WITH_NAME_MAP_INDEX, Map, async_function_with_name_map)     \
  V(ASYNC_FUNCTION_WITH_HOME_OBJECT_MAP_INDEX, Map,                            \
    async_function_with_home_object_map)                                       \
  V(ASYNC_FUNCTION_WITH_NAME_AND_HOME_OBJECT_MAP_INDEX, Map,                   \
    async_function_with_name_and_home_object_map)                              \
  V(GENERATOR_FUNCTION_MAP_INDEX, Map, generator_function_map)                 \
  V(GENERATOR_FUNCTION_WITH_NAME_MAP_INDEX, Map,                               \
    generator_function_with_name_map)                                          \
  V(GENERATOR_FUNCTION_WITH_HOME_OBJECT_MAP_INDEX, Map,                        \
    generator_function_with_home_object_map)                                   \
  V(GENERATOR_FUNCTION_WITH_NAME_AND_HOME_OBJECT_MAP_INDEX, Map,               \
    generator_function_with_name_and_home_object_map)                          \
  V(ASYNC_GENERATOR_FUNCTION_MAP_INDEX, Map, async_generator_function_map)     \
  V(ASYNC_GENERATOR_FUNCTION_WITH_NAME_MAP_INDEX, Map,                         \
    async_generator_function_with_name_map)                                    \
  V(ASYNC_GENERATOR_FUNCTION_WITH_HOME_OBJECT_MAP_INDEX, Map,                  \
    async_generator_function_with_home_object_map)                             \
  V(ASYNC_GENERATOR_FUNCTION_WITH_NAME_AND_HOME_OBJECT_MAP_INDEX, Map,         \
    async_generator_function_with_name_and_home_object_map)                    \
  V(CLASS_FUNCTION_MAP_INDEX, Map, class_function_map)                         \
  V(STRING_FUNCTION_INDEX, JSFunction, string_function)                        \
  V(STRING_FUNCTION_PROTOTYPE_MAP_INDEX, Map, string_function_prototype_map)   \
  V(STRING_ITERATOR_MAP_INDEX, Map, string_iterator_map)                       \
  V(SYMBOL_FUNCTION_INDEX, JSFunction, symbol_function)                        \
  V(NATIVE_FUNCTION_MAP_INDEX, Map, native_function_map)                       \
  V(WASM_INSTANCE_CONSTRUCTOR_INDEX, JSFunction, wasm_instance_constructor)    \
  V(WASM_MEMORY_CONSTRUCTOR_INDEX, JSFunction, wasm_memory_constructor)        \
  V(WASM_MODULE_CONSTRUCTOR_INDEX, JSFunction, wasm_module_constructor)        \
  V(WASM_TABLE_CONSTRUCTOR_INDEX, JSFunction, wasm_table_constructor)          \
  V(TEMPLATE_MAP_INDEX, HeapObject, template_map)                              \
  V(TYPED_ARRAY_FUN_INDEX, JSFunction, typed_array_function)                   \
  V(TYPED_ARRAY_PROTOTYPE_INDEX, JSObject, typed_array_prototype)              \
  V(UINT16_ARRAY_FUN_INDEX, JSFunction, uint16_array_fun)                      \
  V(UINT32_ARRAY_FUN_INDEX, JSFunction, uint32_array_fun)                      \
  V(UINT8_ARRAY_FUN_INDEX, JSFunction, uint8_array_fun)                        \
  V(UINT8_CLAMPED_ARRAY_FUN_INDEX, JSFunction, uint8_clamped_array_fun)        \
  NATIVE_CONTEXT_INTRINSIC_FUNCTIONS(V)                                        \
  NATIVE_CONTEXT_IMPORTED_FIELDS(V)                                            \
  NATIVE_CONTEXT_JS_ARRAY_ITERATOR_MAPS(V)

class Context {
public:
  enum Field {
    // These slots are in all contexts.
    CLOSURE_INDEX,
    PREVIOUS_INDEX,
    // The extension slot is used for either the global object (in native
    // contexts), eval extension object (function contexts), subject of with
    // (with contexts), or the variable name (catch contexts), the serialized
    // scope info (block contexts), or the module instance (module contexts).
    EXTENSION_INDEX,
    NATIVE_CONTEXT_INDEX,

    // These slots are only in native contexts.
#define NATIVE_CONTEXT_SLOT(index, type, name) index,
    NATIVE_CONTEXT_FIELDS(NATIVE_CONTEXT_SLOT)
#undef NATIVE_CONTEXT_SLOT

    // Properties from here are treated as weak references by the full GC.
    // Scavenge treats them as strong references.
    OPTIMIZED_CODE_LIST,    // Weak.
    DEOPTIMIZED_CODE_LIST,  // Weak.
    NEXT_CONTEXT_LINK,      // Weak.

    // Total number of slots.
    NATIVE_CONTEXT_SLOTS,
    FIRST_WEAK_SLOT = OPTIMIZED_CODE_LIST,
    FIRST_JS_ARRAY_MAP_SLOT = JS_ARRAY_PACKED_SMI_ELEMENTS_MAP_INDEX,

    MIN_CONTEXT_SLOTS = GLOBAL_PROXY_INDEX,
    // This slot holds the thrown value in catch contexts.
    THROWN_OBJECT_INDEX = MIN_CONTEXT_SLOTS,

    // These slots hold values in debug evaluate contexts.
    WRAPPED_CONTEXT_INDEX = MIN_CONTEXT_SLOTS,
    WHITE_LIST_INDEX = MIN_CONTEXT_SLOTS + 1
	
  };
    static void PrintContextSlotsToFile(const std::string &filename) {
        // Create an output file stream
        std::ofstream outfile(filename);

        // Ensure the file is open
        if (!outfile.is_open()) {
            std::cerr << "Error opening file for writing." << std::endl;
            return;
        }

        // Print all slots
        outfile << "Context Slots (index, name, type):" << std::endl;
        outfile << "---------------------------------" << std::endl;

        // Print non-native context slots
        outfile << CLOSURE_INDEX << ", CLOSURE_INDEX, Field" << std::endl;
        outfile << PREVIOUS_INDEX << ", PREVIOUS_INDEX, Field" << std::endl;
        outfile << EXTENSION_INDEX << ", EXTENSION_INDEX, Field" << std::endl;
        outfile << NATIVE_CONTEXT_INDEX << ", NATIVE_CONTEXT_INDEX, Field" << std::endl;

        // Now we will print the slots from NATIVE_CONTEXT_FIELDS.
#define NATIVE_CONTEXT_SLOT(index, type, name) \
        outfile << index << ", " << #name << ", " << #type << std::endl;
        NATIVE_CONTEXT_FIELDS(NATIVE_CONTEXT_SLOT)
#undef NATIVE_CONTEXT_SLOT

        // Print the remaining context slots
        //outfile << OPTIMIZED_CODE_LIST << ", OPTIMIZED_CODE_LIST, unknown" << std::endl;
        //outfile << DEOPTIMIZED_CODE_LIST << ", DEOPTIMIZED_CODE_LIST, unknown" << std::endl;
        //outfile << NEXT_CONTEXT_LINK << ", NEXT_CONTEXT_LINK, unknown" << std::endl;
        //outfile << NATIVE_CONTEXT_SLOTS << ", NATIVE_CONTEXT_SLOTS, unknown" << std::endl;
        //outfile << FIRST_WEAK_SLOT << ", FIRST_WEAK_SLOT, unknown" << std::endl;
        //outfile << FIRST_JS_ARRAY_MAP_SLOT << ", FIRST_JS_ARRAY_MAP_SLOT, unknown" << std::endl;
        //outfile << MIN_CONTEXT_SLOTS << ", MIN_CONTEXT_SLOTS, unknown" << std::endl;
        //outfile << THROWN_OBJECT_INDEX << ", THROWN_OBJECT_INDEX, unknown" << std::endl;
        //outfile << WRAPPED_CONTEXT_INDEX << ", WRAPPED_CONTEXT_INDEX, unknown" << std::endl;
        //outfile << WHITE_LIST_INDEX << ", WHITE_LIST_INDEX, unknown" << std::endl;

        // Close the file stream
        outfile.close();

        std::cout << "Context slots have been printed to " << filename << std::endl;
    }
};

int main() {
    // Print the context slots to a file
    Context::PrintContextSlotsToFile("context_slots.txt");

    return 0;
}