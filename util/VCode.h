/*
 * SMHasher3
 * Copyright (C) 2021-2022  Frank J. T. Wojcik
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 */
//-----------------------------------------------------------------------------
// We want the capability to verify that every test produces the same
// result on every platform.  To do this, we hash the results of every
// test to produce an overall verification value for the whole test
// suite. If two runs produce the same verification value, then every
// test in both run produced the same results
//-----------------------------------------------------------------------------
extern uint32_t g_doVCode;

void VCODE_INIT(void);
uint32_t VCODE_FINALIZE(void);

void VCodeWrappedHash ( const void * key, int len, uint32_t seed, void * out );

//-----------------------------------------------------------------------------
void VCODE_HASH(const void * input, size_t len, unsigned idx);

static inline void addVCodeInput(const void * in, size_t len) {
    if (g_doVCode) VCODE_HASH(in, len, 0);
}

static inline void addVCodeOutput(const void * in, size_t len) {
    if (g_doVCode) VCODE_HASH(in, len, 1);
}

static inline void addVCodeResult(const void * in, size_t len) {
    if (g_doVCode) VCODE_HASH(in, len, 2);
}

template < typename T >
static inline void addVCodeInput(const T data) {
    if (g_doVCode) addVCodeInput(&data, sizeof(data));
}

template < typename T >
static inline void addVCodeOutput(const T data) {
    if (g_doVCode) addVCodeOutput(&data, sizeof(data));
}

template < typename T >
static inline void addVCodeResult(const T data) {
    if (g_doVCode) addVCodeResult(&data, sizeof(data));
}
