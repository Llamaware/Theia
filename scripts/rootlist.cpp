#include <iostream>
#include <fstream>
#include <string>
#include <utility>

#define STRONG_ROOT_LIST(V)                                                    \
  /* Cluster the most popular ones in a few cache lines here at the top.    */ \
  /* The first 32 entries are most often used in the startup snapshot and   */ \
  /* can use a shorter representation in the serialization format.          */ \
  V(Map, free_space_map, FreeSpaceMap)                                         \
  V(Map, one_pointer_filler_map, OnePointerFillerMap)                          \
  V(Map, two_pointer_filler_map, TwoPointerFillerMap)                          \
  V(Oddball, uninitialized_value, UninitializedValue)                          \
  V(Oddball, undefined_value, UndefinedValue)                                  \
  V(Oddball, the_hole_value, TheHoleValue)                                     \
  V(Oddball, null_value, NullValue)                                            \
  V(Oddball, true_value, TrueValue)                                            \
  V(Oddball, false_value, FalseValue)                                          \
  V(String, empty_string, empty_string)                                        \
  V(Map, meta_map, MetaMap)                                                    \
  V(Map, byte_array_map, ByteArrayMap)                                         \
  V(Map, fixed_array_map, FixedArrayMap)                                       \
  V(Map, fixed_cow_array_map, FixedCOWArrayMap)                                \
  V(Map, hash_table_map, HashTableMap)                                         \
  V(Map, symbol_map, SymbolMap)                                                \
  V(Map, one_byte_string_map, OneByteStringMap)                                \
  V(Map, one_byte_internalized_string_map, OneByteInternalizedStringMap)       \
  V(Map, scope_info_map, ScopeInfoMap)                                         \
  V(Map, shared_function_info_map, SharedFunctionInfoMap)                      \
  V(Map, code_map, CodeMap)                                                    \
  V(Map, function_context_map, FunctionContextMap)                             \
  V(Map, cell_map, CellMap)                                                    \
  V(Map, weak_cell_map, WeakCellMap)                                           \
  V(Map, global_property_cell_map, GlobalPropertyCellMap)                      \
  V(Map, foreign_map, ForeignMap)                                              \
  V(Map, heap_number_map, HeapNumberMap)                                       \
  V(Map, transition_array_map, TransitionArrayMap)                             \
  V(Map, feedback_vector_map, FeedbackVectorMap)                               \
  V(ScopeInfo, empty_scope_info, EmptyScopeInfo)                               \
  V(FixedArray, empty_fixed_array, EmptyFixedArray)                            \
  V(DescriptorArray, empty_descriptor_array, EmptyDescriptorArray)             \
  /* Entries beyond the first 32                                            */ \
  /* The roots above this line should be boring from a GC point of view.    */ \
  /* This means they are never in new space and never on a page that is     */ \
  /* being compacted.                                                       */ \
  /* Oddballs */                                                               \
  V(Oddball, arguments_marker, ArgumentsMarker)                                \
  V(Oddball, exception, Exception)                                             \
  V(Oddball, termination_exception, TerminationException)                      \
  V(Oddball, optimized_out, OptimizedOut)                                      \
  V(Oddball, stale_register, StaleRegister)                                    \
  /* Context maps */                                                           \
  V(Map, native_context_map, NativeContextMap)                                 \
  V(Map, module_context_map, ModuleContextMap)                                 \
  V(Map, eval_context_map, EvalContextMap)                                     \
  V(Map, script_context_map, ScriptContextMap)                                 \
  V(Map, block_context_map, BlockContextMap)                                   \
  V(Map, catch_context_map, CatchContextMap)                                   \
  V(Map, with_context_map, WithContextMap)                                     \
  V(Map, debug_evaluate_context_map, DebugEvaluateContextMap)                  \
  V(Map, script_context_table_map, ScriptContextTableMap)                      \
  /* Maps */                                                                   \
  V(Map, descriptor_array_map, DescriptorArrayMap)                             \
  V(Map, array_list_map, ArrayListMap)                                         \
  V(Map, fixed_double_array_map, FixedDoubleArrayMap)                          \
  V(Map, mutable_heap_number_map, MutableHeapNumberMap)                        \
  V(Map, ordered_hash_map_map, OrderedHashMapMap)                              \
  V(Map, ordered_hash_set_map, OrderedHashSetMap)                              \
  V(Map, name_dictionary_map, NameDictionaryMap)                               \
  V(Map, global_dictionary_map, GlobalDictionaryMap)                           \
  V(Map, number_dictionary_map, NumberDictionaryMap)                           \
  V(Map, string_table_map, StringTableMap)                                     \
  V(Map, weak_hash_table_map, WeakHashTableMap)                                \
  V(Map, sloppy_arguments_elements_map, SloppyArgumentsElementsMap)            \
  V(Map, small_ordered_hash_map_map, SmallOrderedHashMapMap)                   \
  V(Map, small_ordered_hash_set_map, SmallOrderedHashSetMap)                   \
  V(Map, code_data_container_map, CodeDataContainerMap)                        \
  V(Map, message_object_map, JSMessageObjectMap)                               \
  V(Map, external_map, ExternalMap)                                            \
  V(Map, bytecode_array_map, BytecodeArrayMap)                                 \
  V(Map, module_info_map, ModuleInfoMap)                                       \
  V(Map, no_closures_cell_map, NoClosuresCellMap)                              \
  V(Map, one_closure_cell_map, OneClosureCellMap)                              \
  V(Map, many_closures_cell_map, ManyClosuresCellMap)                          \
  V(Map, property_array_map, PropertyArrayMap)                                 \
  V(Map, bigint_map, BigIntMap)                                                \
  /* String maps */                                                            \
  V(Map, native_source_string_map, NativeSourceStringMap)                      \
  V(Map, string_map, StringMap)                                                \
  V(Map, cons_one_byte_string_map, ConsOneByteStringMap)                       \
  V(Map, cons_string_map, ConsStringMap)                                       \
  V(Map, thin_one_byte_string_map, ThinOneByteStringMap)                       \
  V(Map, thin_string_map, ThinStringMap)                                       \
  V(Map, sliced_string_map, SlicedStringMap)                                   \
  V(Map, sliced_one_byte_string_map, SlicedOneByteStringMap)                   \
  V(Map, external_string_map, ExternalStringMap)                               \
  V(Map, external_string_with_one_byte_data_map,                               \
    ExternalStringWithOneByteDataMap)                                          \
  V(Map, external_one_byte_string_map, ExternalOneByteStringMap)               \
  V(Map, short_external_string_map, ShortExternalStringMap)                    \
  V(Map, short_external_string_with_one_byte_data_map,                         \
    ShortExternalStringWithOneByteDataMap)                                     \
  V(Map, internalized_string_map, InternalizedStringMap)                       \
  V(Map, external_internalized_string_map, ExternalInternalizedStringMap)      \
  V(Map, external_internalized_string_with_one_byte_data_map,                  \
    ExternalInternalizedStringWithOneByteDataMap)                              \
  V(Map, external_one_byte_internalized_string_map,                            \
    ExternalOneByteInternalizedStringMap)                                      \
  V(Map, short_external_internalized_string_map,                               \
    ShortExternalInternalizedStringMap)                                        \
  V(Map, short_external_internalized_string_with_one_byte_data_map,            \
    ShortExternalInternalizedStringWithOneByteDataMap)                         \
  V(Map, short_external_one_byte_internalized_string_map,                      \
    ShortExternalOneByteInternalizedStringMap)                                 \
  V(Map, short_external_one_byte_string_map, ShortExternalOneByteStringMap)    \
  /* Array element maps */                                                     \
  V(Map, fixed_uint8_array_map, FixedUint8ArrayMap)                            \
  V(Map, fixed_int8_array_map, FixedInt8ArrayMap)                              \
  V(Map, fixed_uint16_array_map, FixedUint16ArrayMap)                          \
  V(Map, fixed_int16_array_map, FixedInt16ArrayMap)                            \
  V(Map, fixed_uint32_array_map, FixedUint32ArrayMap)                          \
  V(Map, fixed_int32_array_map, FixedInt32ArrayMap)                            \
  V(Map, fixed_float32_array_map, FixedFloat32ArrayMap)                        \
  V(Map, fixed_float64_array_map, FixedFloat64ArrayMap)                        \
  V(Map, fixed_uint8_clamped_array_map, FixedUint8ClampedArrayMap)             \
  /* Oddball maps */                                                           \
  V(Map, undefined_map, UndefinedMap)                                          \
  V(Map, the_hole_map, TheHoleMap)                                             \
  V(Map, null_map, NullMap)                                                    \
  V(Map, boolean_map, BooleanMap)                                              \
  V(Map, uninitialized_map, UninitializedMap)                                  \
  V(Map, arguments_marker_map, ArgumentsMarkerMap)                             \
  V(Map, exception_map, ExceptionMap)                                          \
  V(Map, termination_exception_map, TerminationExceptionMap)                   \
  V(Map, optimized_out_map, OptimizedOutMap)                                   \
  V(Map, stale_register_map, StaleRegisterMap)                                 \
  /* Canonical empty values */                                                 \
  V(EnumCache, empty_enum_cache, EmptyEnumCache)                               \
  V(PropertyArray, empty_property_array, EmptyPropertyArray)                   \
  V(ByteArray, empty_byte_array, EmptyByteArray)                               \
  V(FixedTypedArrayBase, empty_fixed_uint8_array, EmptyFixedUint8Array)        \
  V(FixedTypedArrayBase, empty_fixed_int8_array, EmptyFixedInt8Array)          \
  V(FixedTypedArrayBase, empty_fixed_uint16_array, EmptyFixedUint16Array)      \
  V(FixedTypedArrayBase, empty_fixed_int16_array, EmptyFixedInt16Array)        \
  V(FixedTypedArrayBase, empty_fixed_uint32_array, EmptyFixedUint32Array)      \
  V(FixedTypedArrayBase, empty_fixed_int32_array, EmptyFixedInt32Array)        \
  V(FixedTypedArrayBase, empty_fixed_float32_array, EmptyFixedFloat32Array)    \
  V(FixedTypedArrayBase, empty_fixed_float64_array, EmptyFixedFloat64Array)    \
  V(FixedTypedArrayBase, empty_fixed_uint8_clamped_array,                      \
    EmptyFixedUint8ClampedArray)                                               \
  V(Script, empty_script, EmptyScript)                                         \
  V(Cell, undefined_cell, UndefinedCell)                                       \
  V(FixedArray, empty_sloppy_arguments_elements, EmptySloppyArgumentsElements) \
  V(NumberDictionary, empty_slow_element_dictionary,                           \
    EmptySlowElementDictionary)                                                \
  V(FixedArray, empty_ordered_hash_map, EmptyOrderedHashMap)                   \
  V(FixedArray, empty_ordered_hash_set, EmptyOrderedHashSet)                   \
  V(PropertyCell, empty_property_cell, EmptyPropertyCell)                      \
  V(WeakCell, empty_weak_cell, EmptyWeakCell)                                  \
  V(InterceptorInfo, noop_interceptor_info, NoOpInterceptorInfo)               \
  /* Protectors */                                                             \
  V(Cell, array_constructor_protector, ArrayConstructorProtector)              \
  V(PropertyCell, no_elements_protector, NoElementsProtector)                  \
  V(Cell, is_concat_spreadable_protector, IsConcatSpreadableProtector)         \
  V(PropertyCell, species_protector, SpeciesProtector)                         \
  V(Cell, string_length_protector, StringLengthProtector)                      \
  V(Cell, fast_array_iteration_protector, FastArrayIterationProtector)         \
  V(PropertyCell, array_iterator_protector, ArrayIteratorProtector)            \
  V(PropertyCell, array_buffer_neutering_protector,                            \
    ArrayBufferNeuteringProtector)                                             \
  /* Special numbers */                                                        \
  V(HeapNumber, nan_value, NanValue)                                           \
  V(HeapNumber, hole_nan_value, HoleNanValue)                                  \
  V(HeapNumber, infinity_value, InfinityValue)                                 \
  V(HeapNumber, minus_zero_value, MinusZeroValue)                              \
  V(HeapNumber, minus_infinity_value, MinusInfinityValue)                      \
  /* Caches */                                                                 \
  V(FixedArray, number_string_cache, NumberStringCache)                        \
  V(FixedArray, single_character_string_cache, SingleCharacterStringCache)     \
  V(FixedArray, string_split_cache, StringSplitCache)                          \
  V(FixedArray, regexp_multiple_cache, RegExpMultipleCache)                    \
  /* Lists and dictionaries */                                                 \
  V(NameDictionary, empty_property_dictionary, EmptyPropertyDictionary)        \
  V(NameDictionary, public_symbol_table, PublicSymbolTable)                    \
  V(NameDictionary, api_symbol_table, ApiSymbolTable)                          \
  V(NameDictionary, api_private_symbol_table, ApiPrivateSymbolTable)           \
  V(Object, script_list, ScriptList)                                           \
  V(NumberDictionary, code_stubs, CodeStubs)                                   \
  V(FixedArray, materialized_objects, MaterializedObjects)                     \
  V(FixedArray, microtask_queue, MicrotaskQueue)                               \
  V(FixedArray, detached_contexts, DetachedContexts)                           \
  V(HeapObject, retaining_path_targets, RetainingPathTargets)                  \
  V(ArrayList, retained_maps, RetainedMaps)                                    \
  V(WeakHashTable, weak_object_to_code_table, WeakObjectToCodeTable)           \
  /* weak_new_space_object_to_code_list is an array of weak cells, where */    \
  /* slots with even indices refer to the weak object, and the subsequent */   \
  /* slots refer to the code with the reference to the weak object. */         \
  V(ArrayList, weak_new_space_object_to_code_list,                             \
    WeakNewSpaceObjectToCodeList)                                              \
  /* Feedback vectors that we need for code coverage or type profile */        \
  V(Object, feedback_vectors_for_profiling_tools,                              \
    FeedbackVectorsForProfilingTools)                                          \
  V(Object, weak_stack_trace_list, WeakStackTraceList)                         \
  V(Object, noscript_shared_function_infos, NoScriptSharedFunctionInfos)       \
  V(FixedArray, serialized_objects, SerializedObjects)                         \
  V(FixedArray, serialized_global_proxy_sizes, SerializedGlobalProxySizes)     \
  V(TemplateList, message_listeners, MessageListeners)                         \
  /* DeserializeLazy handlers for lazy bytecode deserialization */             \
  V(Object, deserialize_lazy_handler, DeserializeLazyHandler)                  \
  V(Object, deserialize_lazy_handler_wide, DeserializeLazyHandlerWide)         \
  V(Object, deserialize_lazy_handler_extra_wide,                               \
    DeserializeLazyHandlerExtraWide)                                           \
  /* JS Entries */                                                             \
  V(Code, js_entry_code, JsEntryCode)                                          \
  V(Code, js_construct_entry_code, JsConstructEntryCode)                       \
  V(Code, js_run_microtasks_entry_code, JsRunMicrotasksEntryCode)



#define INTERNALIZED_STRING_LIST(V)                                         \
  V(anonymous_function_string, "(anonymous function)")                      \
  V(anonymous_string, "anonymous")                                          \
  V(add_string, "add")                                                      \
  V(apply_string, "apply")                                                  \
  V(arguments_string, "arguments")                                          \
  V(Arguments_string, "Arguments")                                          \
  V(arguments_to_string, "[object Arguments]")                              \
  V(Array_string, "Array")                                                  \
  V(ArrayIterator_string, "Array Iterator")                                 \
  V(assign_string, "assign")                                                \
  V(async_string, "async")                                                  \
  V(await_string, "await")                                                  \
  V(array_to_string, "[object Array]")                                      \
  V(boolean_to_string, "[object Boolean]")                                  \
  V(date_to_string, "[object Date]")                                        \
  V(error_to_string, "[object Error]")                                      \
  V(function_to_string, "[object Function]")                                \
  V(number_to_string, "[object Number]")                                    \
  V(object_to_string, "[object Object]")                                    \
  V(regexp_to_string, "[object RegExp]")                                    \
  V(string_to_string, "[object String]")                                    \
  V(bigint_string, "bigint")                                                \
  V(BigInt_string, "BigInt")                                                \
  V(bind_string, "bind")                                                    \
  V(boolean_string, "boolean")                                              \
  V(Boolean_string, "Boolean")                                              \
  V(bound__string, "bound ")                                                \
  V(buffer_string, "buffer")                                                \
  V(byte_length_string, "byteLength")                                       \
  V(byte_offset_string, "byteOffset")                                       \
  V(call_string, "call")                                                    \
  V(callee_string, "callee")                                                \
  V(caller_string, "caller")                                                \
  V(cell_value_string, "%cell_value")                                       \
  V(char_at_string, "CharAt")                                               \
  V(closure_string, "(closure)")                                            \
  V(column_string, "column")                                                \
  V(configurable_string, "configurable")                                    \
  V(constructor_string, "constructor")                                      \
  V(construct_string, "construct")                                          \
  V(create_string, "create")                                                \
  V(currency_string, "currency")                                            \
  V(Date_string, "Date")                                                    \
  V(dayperiod_string, "dayperiod")                                          \
  V(day_string, "day")                                                      \
  V(decimal_string, "decimal")                                              \
  V(default_string, "default")                                              \
  V(defineProperty_string, "defineProperty")                                \
  V(deleteProperty_string, "deleteProperty")                                \
  V(did_handle_string, "didHandle")                                         \
  V(display_name_string, "displayName")                                     \
  V(done_string, "done")                                                    \
  V(dotAll_string, "dotAll")                                                \
  V(dot_catch_string, ".catch")                                             \
  V(dot_for_string, ".for")                                                 \
  V(dot_generator_object_string, ".generator_object")                       \
  V(dot_iterator_string, ".iterator")                                       \
  V(dot_result_string, ".result")                                           \
  V(dot_switch_tag_string, ".switch_tag")                                   \
  V(dot_string, ".")                                                        \
  V(exec_string, "exec")                                                    \
  V(entries_string, "entries")                                              \
  V(enqueue_string, "enqueue")                                              \
  V(enumerable_string, "enumerable")                                        \
  V(era_string, "era")                                                      \
  V(Error_string, "Error")                                                  \
  V(eval_string, "eval")                                                    \
  V(EvalError_string, "EvalError")                                          \
  V(false_string, "false")                                                  \
  V(flags_string, "flags")                                                  \
  V(fraction_string, "fraction")                                            \
  V(function_string, "function")                                            \
  V(Function_string, "Function")                                            \
  V(Generator_string, "Generator")                                          \
  V(getOwnPropertyDescriptor_string, "getOwnPropertyDescriptor")            \
  V(getOwnPropertyDescriptors_string, "getOwnPropertyDescriptors")          \
  V(getPrototypeOf_string, "getPrototypeOf")                                \
  V(get_string, "get")                                                      \
  V(get_space_string, "get ")                                               \
  V(global_string, "global")                                                \
  V(group_string, "group")                                                  \
  V(groups_string, "groups")                                                \
  V(has_string, "has")                                                      \
  V(hour_string, "hour")                                                    \
  V(ignoreCase_string, "ignoreCase")                                        \
  V(illegal_access_string, "illegal access")                                \
  V(illegal_argument_string, "illegal argument")                            \
  V(index_string, "index")                                                  \
  V(infinity_string, "infinity")                                            \
  V(Infinity_string, "Infinity")                                            \
  V(integer_string, "integer")                                              \
  V(input_string, "input")                                                  \
  V(isExtensible_string, "isExtensible")                                    \
  V(isView_string, "isView")                                                \
  V(KeyedLoadMonomorphic_string, "KeyedLoadMonomorphic")                    \
  V(KeyedStoreMonomorphic_string, "KeyedStoreMonomorphic")                  \
  V(keys_string, "keys")                                                    \
  V(lastIndex_string, "lastIndex")                                          \
  V(length_string, "length")                                                \
  V(let_string, "let")                                                      \
  V(line_string, "line")                                                    \
  V(literal_string, "literal")                                              \
  V(Map_string, "Map")                                                      \
  V(message_string, "message")                                              \
  V(minus_Infinity_string, "-Infinity")                                     \
  V(minus_zero_string, "-0")                                                \
  V(minusSign_string, "minusSign")                                          \
  V(minute_string, "minute")                                                \
  V(Module_string, "Module")                                                \
  V(month_string, "month")                                                  \
  V(multiline_string, "multiline")                                          \
  V(name_string, "name")                                                    \
  V(native_string, "native")                                                \
  V(nan_string, "nan")                                                      \
  V(NaN_string, "NaN")                                                      \
  V(new_target_string, ".new.target")                                       \
  V(next_string, "next")                                                    \
  V(NFC_string, "NFC")                                                      \
  V(NFD_string, "NFD")                                                      \
  V(NFKC_string, "NFKC")                                                    \
  V(NFKD_string, "NFKD")                                                    \
  V(not_equal, "not-equal")                                                 \
  V(null_string, "null")                                                    \
  V(null_to_string, "[object Null]")                                        \
  V(number_string, "number")                                                \
  V(Number_string, "Number")                                                \
  V(object_string, "object")                                                \
  V(Object_string, "Object")                                                \
  V(ok, "ok")                                                               \
  V(one_string, "1")                                                        \
  V(ownKeys_string, "ownKeys")                                              \
  V(percentSign_string, "percentSign")                                      \
  V(plusSign_string, "plusSign")                                            \
  V(position_string, "position")                                            \
  V(preventExtensions_string, "preventExtensions")                          \
  V(Promise_string, "Promise")                                              \
  V(PromiseResolveThenableJob_string, "PromiseResolveThenableJob")          \
  V(promise_string, "promise")                                              \
  V(proto_string, "__proto__")                                              \
  V(prototype_string, "prototype")                                          \
  V(proxy_string, "proxy")                                                  \
  V(Proxy_string, "Proxy")                                                  \
  V(query_colon_string, "(?:)")                                             \
  V(RangeError_string, "RangeError")                                        \
  V(raw_string, "raw")                                                      \
  V(ReferenceError_string, "ReferenceError")                                \
  V(RegExp_string, "RegExp")                                                \
  V(reject_string, "reject")                                                \
  V(resolve_string, "resolve")                                              \
  V(return_string, "return")                                                \
  V(revoke_string, "revoke")                                                \
  V(script_string, "script")                                                \
  V(second_string, "second")                                                \
  V(setPrototypeOf_string, "setPrototypeOf")                                \
  V(set_space_string, "set ")                                               \
  V(set_string, "set")                                                      \
  V(Set_string, "Set")                                                      \
  V(source_string, "source")                                                \
  V(sourceText_string, "sourceText")                                        \
  V(stack_string, "stack")                                                  \
  V(stackTraceLimit_string, "stackTraceLimit")                              \
  V(star_default_star_string, "*default*")                                  \
  V(sticky_string, "sticky")                                                \
  V(string_string, "string")                                                \
  V(String_string, "String")                                                \
  V(symbol_string, "symbol")                                                \
  V(Symbol_string, "Symbol")                                                \
  V(symbol_species_string, "[Symbol.species]")                              \
  V(SyntaxError_string, "SyntaxError")                                      \
  V(then_string, "then")                                                    \
  V(this_function_string, ".this_function")                                 \
  V(this_string, "this")                                                    \
  V(throw_string, "throw")                                                  \
  V(timed_out, "timed-out")                                                 \
  V(timeZoneName_string, "timeZoneName")                                    \
  V(toJSON_string, "toJSON")                                                \
  V(toString_string, "toString")                                            \
  V(true_string, "true")                                                    \
  V(TypeError_string, "TypeError")                                          \
  V(type_string, "type")                                                    \
  V(CompileError_string, "CompileError")                                    \
  V(LinkError_string, "LinkError")                                          \
  V(RuntimeError_string, "RuntimeError")                                    \
  V(undefined_string, "undefined")                                          \
  V(undefined_to_string, "[object Undefined]")                              \
  V(unicode_string, "unicode")                                              \
  V(use_asm_string, "use asm")                                              \
  V(use_strict_string, "use strict")                                        \
  V(URIError_string, "URIError")                                            \
  V(valueOf_string, "valueOf")                                              \
  V(values_string, "values")                                                \
  V(value_string, "value")                                                  \
  V(WeakMap_string, "WeakMap")                                              \
  V(WeakSet_string, "WeakSet")                                              \
  V(weekday_string, "weekday")                                              \
  V(will_handle_string, "willHandle")                                       \
  V(writable_string, "writable")                                            \
  V(year_string, "year")                                                    \
  V(zero_string, "0")


#define PRIVATE_SYMBOL_LIST(V)              \
  V(array_iteration_kind_symbol)            \
  V(array_iterator_next_symbol)             \
  V(array_iterator_object_symbol)           \
  V(call_site_frame_array_symbol)           \
  V(call_site_frame_index_symbol)           \
  V(console_context_id_symbol)              \
  V(console_context_name_symbol)            \
  V(class_fields_symbol)                    \
  V(class_positions_symbol)                 \
  V(detailed_stack_trace_symbol)            \
  V(elements_transition_symbol)             \
  V(error_end_pos_symbol)                   \
  V(error_script_symbol)                    \
  V(error_start_pos_symbol)                 \
  V(frozen_symbol)                          \
  V(generic_symbol)                         \
  V(home_object_symbol)                     \
  V(intl_initialized_marker_symbol)         \
  V(intl_pattern_symbol)                    \
  V(intl_resolved_symbol)                   \
  V(megamorphic_symbol)                     \
  V(native_context_index_symbol)            \
  V(nonextensible_symbol)                   \
  V(not_mapped_symbol)                      \
  V(premonomorphic_symbol)                  \
  V(promise_async_stack_id_symbol)          \
  V(promise_debug_marker_symbol)            \
  V(promise_forwarding_handler_symbol)      \
  V(promise_handled_by_symbol)              \
  V(promise_async_id_symbol)                \
  V(promise_default_resolve_handler_symbol) \
  V(promise_default_reject_handler_symbol)  \
  V(sealed_symbol)                          \
  V(stack_trace_symbol)                     \
  V(strict_function_transition_symbol)      \
  V(wasm_function_index_symbol)             \
  V(wasm_instance_symbol)                   \
  V(uninitialized_symbol)


#define PUBLIC_SYMBOL_LIST(V)                    \
  V(async_iterator_symbol, Symbol.asyncIterator) \
  V(iterator_symbol, Symbol.iterator)            \
  V(intl_fallback_symbol, IntlFallback)          \
  V(match_symbol, Symbol.match)                  \
  V(replace_symbol, Symbol.replace)              \
  V(search_symbol, Symbol.search)                \
  V(species_symbol, Symbol.species)              \
  V(split_symbol, Symbol.split)                  \
  V(to_primitive_symbol, Symbol.toPrimitive)     \
  V(unscopables_symbol, Symbol.unscopables)



#define WELL_KNOWN_SYMBOL_LIST(V)                           \
  V(has_instance_symbol, Symbol.hasInstance)                \
  V(is_concat_spreadable_symbol, Symbol.isConcatSpreadable) \
  V(to_string_tag_symbol, Symbol.toStringTag)


#define ACCESSOR_INFO_LIST(V)                                       \
  V(arguments_iterator, ArgumentsIterator)                          \
  V(array_length, ArrayLength)                                      \
  V(bound_function_length, BoundFunctionLength)                     \
  V(bound_function_name, BoundFunctionName)                         \
  V(error_stack, ErrorStack)                                        \
  V(function_arguments, FunctionArguments)                          \
  V(function_caller, FunctionCaller)                                \
  V(function_name, FunctionName)                                    \
  V(function_length, FunctionLength)                                \
  V(function_prototype, FunctionPrototype)                          \
  V(script_column_offset, ScriptColumnOffset)                       \
  V(script_compilation_type, ScriptCompilationType)                 \
  V(script_context_data, ScriptContextData)                         \
  V(script_eval_from_script, ScriptEvalFromScript)                  \
  V(script_eval_from_script_position, ScriptEvalFromScriptPosition) \
  V(script_eval_from_function_name, ScriptEvalFromFunctionName)     \
  V(script_id, ScriptId)                                            \
  V(script_line_offset, ScriptLineOffset)                           \
  V(script_name, ScriptName)                                        \
  V(script_source, ScriptSource)                                    \
  V(script_type, ScriptType)                                        \
  V(script_source_url, ScriptSourceUrl)                             \
  V(script_source_mapping_url, ScriptSourceMappingUrl)              \
  V(string_length, StringLength)


#define STRUCT_LIST(V)                                                       \
  V(ACCESS_CHECK_INFO, AccessCheckInfo, access_check_info)                   \
  V(ACCESSOR_INFO, AccessorInfo, accessor_info)                              \
  V(ACCESSOR_PAIR, AccessorPair, accessor_pair)                              \
  V(ALIASED_ARGUMENTS_ENTRY, AliasedArgumentsEntry, aliased_arguments_entry) \
  V(ALLOCATION_MEMENTO, AllocationMemento, allocation_memento)               \
  V(ALLOCATION_SITE, AllocationSite, allocation_site)                        \
  V(ASYNC_GENERATOR_REQUEST, AsyncGeneratorRequest, async_generator_request) \
  V(CONTEXT_EXTENSION, ContextExtension, context_extension)                  \
  V(DEBUG_INFO, DebugInfo, debug_info)                                       \
  V(FUNCTION_TEMPLATE_INFO, FunctionTemplateInfo, function_template_info)    \
  V(INTERCEPTOR_INFO, InterceptorInfo, interceptor_info)                     \
  V(MODULE_INFO_ENTRY, ModuleInfoEntry, module_info_entry)                   \
  V(MODULE, Module, module)                                                  \
  V(OBJECT_TEMPLATE_INFO, ObjectTemplateInfo, object_template_info)          \
  V(PROMISE_REACTION_JOB_INFO, PromiseReactionJobInfo,                       \
    promise_reaction_job_info)                                               \
  V(PROMISE_RESOLVE_THENABLE_JOB_INFO, PromiseResolveThenableJobInfo,        \
    promise_resolve_thenable_job_info)                                       \
  V(PROTOTYPE_INFO, PrototypeInfo, prototype_info)                           \
  V(SCRIPT, Script, script)                                                  \
  V(STACK_FRAME_INFO, StackFrameInfo, stack_frame_info)                      \
  V(TUPLE2, Tuple2, tuple2)                                                  \
  V(TUPLE3, Tuple3, tuple3)


#define DATA_HANDLER_LIST(V)                        \
  V(LOAD_HANDLER, LoadHandler, 1, load_handler1)    \
  V(LOAD_HANDLER, LoadHandler, 2, load_handler2)    \
  V(LOAD_HANDLER, LoadHandler, 3, load_handler3)    \
  V(STORE_HANDLER, StoreHandler, 0, store_handler0) \
  V(STORE_HANDLER, StoreHandler, 1, store_handler1) \
  V(STORE_HANDLER, StoreHandler, 2, store_handler2) \
  V(STORE_HANDLER, StoreHandler, 3, store_handler3)

#define SMI_ROOT_LIST(V)                                                       \
  V(Smi, stack_limit, StackLimit)                                              \
  V(Smi, real_stack_limit, RealStackLimit)                                     \
  V(Smi, last_script_id, LastScriptId)                                         \
  V(Smi, hash_seed, HashSeed)                                                  \
  /* To distinguish the function templates, so that we can find them in the */ \
  /* function cache of the native context. */                                  \
  V(Smi, next_template_serial_number, NextTemplateSerialNumber)                \
  V(Smi, arguments_adaptor_deopt_pc_offset, ArgumentsAdaptorDeoptPCOffset)     \
  V(Smi, construct_stub_create_deopt_pc_offset,                                \
    ConstructStubCreateDeoptPCOffset)                                          \
  V(Smi, construct_stub_invoke_deopt_pc_offset,                                \
    ConstructStubInvokeDeoptPCOffset)                                          \
  V(Smi, interpreter_entry_return_pc_offset, InterpreterEntryReturnPCOffset)


class Heap {
public:
enum RootListIndex {
#define DECL(type, name, camel_name) k##camel_name##RootIndex,
    STRONG_ROOT_LIST(DECL)
#undef DECL

#define DECL(name, str) k##name##RootIndex,
    INTERNALIZED_STRING_LIST(DECL)
#undef DECL

#define DECL(name) k##name##RootIndex,
    PRIVATE_SYMBOL_LIST(DECL)
#undef DECL

#define DECL(name, description) k##name##RootIndex,
    PUBLIC_SYMBOL_LIST(DECL)
    WELL_KNOWN_SYMBOL_LIST(DECL)
#undef DECL

#define DECL(accessor_name, AccessorName) k##AccessorName##AccessorRootIndex,
    ACCESSOR_INFO_LIST(DECL)
#undef DECL

#define DECL(NAME, Name, name) k##Name##MapRootIndex,
    STRUCT_LIST(DECL)
#undef DECL

#define DECL(NAME, Name, Size, name) k##Name##Size##MapRootIndex,
    DATA_HANDLER_LIST(DECL)
#undef DECL

    kStringTableRootIndex,

#define DECL(type, name, camel_name) k##camel_name##RootIndex,
    SMI_ROOT_LIST(DECL)
#undef DECL

    kRootListLength,
    kStrongRootListLength = kStringTableRootIndex,
    kSmiRootsStart = kStringTableRootIndex + 1
};


    static std::pair<std::string, std::string> RootListIndexToString(RootListIndex index) {
        switch (index) {
            #define DECL(type, name, camel_name) case k##camel_name##RootIndex: return {#camel_name, #type};
            STRONG_ROOT_LIST(DECL)
            #undef DECL

            #define DECL(name, str) case k##name##RootIndex: return {#name, "string"};
            INTERNALIZED_STRING_LIST(DECL)
            #undef DECL

            #define DECL(name) case k##name##RootIndex: return {#name, "callable"};
            PRIVATE_SYMBOL_LIST(DECL)
            #undef DECL

            #define DECL(name, description) case k##name##RootIndex: return {#name, "callable"};
            PUBLIC_SYMBOL_LIST(DECL)
            WELL_KNOWN_SYMBOL_LIST(DECL)
            #undef DECL

            #define DECL(accessor_name, AccessorName) case k##AccessorName##AccessorRootIndex: return {#AccessorName, "accessor"};
            ACCESSOR_INFO_LIST(DECL)
            #undef DECL

            #define DECL(NAME, Name, name) case k##Name##MapRootIndex: return {#Name, "object"};
            STRUCT_LIST(DECL)
            #undef DECL

            #define DECL(NAME, Name, Size, name) case k##Name##Size##MapRootIndex: return {#name, "handler"};
            DATA_HANDLER_LIST(DECL)
            #undef DECL

            case kStringTableRootIndex:
                return {"kStringTableRootIndex", "string_table"};

            #define DECL(type, name, camel_name) case k##camel_name##RootIndex: return {#camel_name, "int"};
            SMI_ROOT_LIST(DECL)
            #undef DECL

            default:
                return {"Unknown", "unknown"};
        }
    }

    // Function to print both name and type to a file
    static void printRootIndexesToFile(const std::string& filename) {
        std::ofstream file(filename);

        if (file.is_open()) {
            for (int i = 0; i < kRootListLength; ++i) {
                RootListIndex index = static_cast<RootListIndex>(i);
				auto result = RootListIndexToString(index);
                file << i << ", " << result.first << ", " << result.second << std::endl;
            }
            file.close();
            std::cout << "Root list indexes have been written to " << filename << std::endl;
        } else {
            std::cerr << "Failed to open the file " << filename << std::endl;
        }
    }
};


int main() {
    Heap::printRootIndexesToFile("root_indexes.txt");
    return 0;
}