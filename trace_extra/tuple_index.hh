/*-
 * Copyright (c) 2021 Alfredo Mazzinghi
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * @BERI_LICENSE_HEADER_START@
 *
 * Licensed to BERI Open Systems C.I.C. (BERI) under one or more contributor
 * license agreements.  See the NOTICE file distributed with this work for
 * additional information regarding copyright ownership.  BERI licenses this
 * file to you under the BERI Hardware-Software License, Version 1.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at:
 *
 *   http://www.beri-open-systems.org/legal/license-1-0.txt
 *
 * Unless required by applicable law or agreed to in writing, Work distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * @BERI_LICENSE_HEADER_END@
 */

#pragma once

#include <cstddef>
#include <type_traits>
#include <utility>
#include <boost/functional/hash.hpp>

namespace cheri
{
template <typename T> struct is_tuple_impl : std::false_type {
};
template <typename... T>
struct is_tuple_impl<std::tuple<T...>> : std::true_type {
};
template <typename T> struct is_tuple : is_tuple_impl<std::decay_t<T>> {
};

template <typename T, typename Enable = void> struct tuple_hasher;

template <typename T>
struct tuple_hasher<T, typename std::enable_if<is_tuple<T>::value>::type> {
    std::size_t operator()(const T &tuple) const
    {
        return boost::hash_value(tuple);
    }
};
} // namespace cheri
