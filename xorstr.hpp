#pragma once

#include <string>
#include <utility>

namespace
{
	constexpr int const_atoi(char c)
	{
		return c - '0';
	}
}

#ifdef _MSC_VER
#define ALWAYS_INLINE __forceinline
#else
#define ALWAYS_INLINE __attribute__((always_inline))
#endif

constexpr size_t keyauth_xor_build_key(const char* time)
{
    return static_cast<size_t>((time[7] - '0') + (time[6] - '0') * 10 +
        (time[4] - '0') * 60 + (time[3] - '0') * 600 +
        (time[1] - '0') * 3600 + (time[0] - '0') * 36000);
}

template<typename _string_type, size_t _length, size_t _key = keyauth_xor_build_key(__TIME__)>
class _Basic_XorStr
{
	using value_type = typename _string_type::value_type;
	static constexpr auto _length_minus_one = _length - 1;

public:
	constexpr ALWAYS_INLINE _Basic_XorStr(value_type const (&str)[_length])
		: _Basic_XorStr(str, std::make_index_sequence<_length_minus_one>())
	{

	}

	inline auto c_str() const
	{
		decrypt();

		return data;
	}

	inline auto str() const
	{
		_string_type result(_length_minus_one, value_type{});
		for (size_t t = 0; t < _length_minus_one; ++t)
			result[t] = encrypted ? crypt(data[t], t) : data[t];
		return result;
	}

	inline operator _string_type() const
	{
		return str();
	}

private:
	template<size_t... indices>
	constexpr ALWAYS_INLINE _Basic_XorStr(value_type const (&str)[_length], std::index_sequence<indices...>)
		: data{ crypt(str[indices], indices)..., '\0' },
		encrypted(true)
	{

	}

	static constexpr auto XOR_KEY = static_cast<value_type>(_key);

	static ALWAYS_INLINE constexpr auto crypt(value_type c, size_t i)
	{
		return static_cast<value_type>(c ^ (XOR_KEY + i));
	}

	inline void decrypt() const
	{
		if (encrypted)
		{
			for (size_t t = 0; t < _length_minus_one; t++)
			{
				data[t] = crypt(data[t], t);
			}
			encrypted = false;
		}
	}

	mutable value_type data[_length];
	mutable bool encrypted;
};
//---------------------------------------------------------------------------
template<size_t _length, size_t _key = keyauth_xor_build_key(__TIME__)>
using XorStrA = _Basic_XorStr<std::string, _length, _key>;
template<size_t _length, size_t _key = keyauth_xor_build_key(__TIME__)>
using XorStrW = _Basic_XorStr<std::wstring, _length, _key>;
template<size_t _length, size_t _key = keyauth_xor_build_key(__TIME__)>
using XorStrU16 = _Basic_XorStr<std::u16string, _length, _key>;
template<size_t _length, size_t _key = keyauth_xor_build_key(__TIME__)>
using XorStrU32 = _Basic_XorStr<std::u32string, _length, _key>;
//---------------------------------------------------------------------------
template<typename _string_type, size_t _length, size_t _key, size_t _length2, size_t _key2>
inline auto operator==(const _Basic_XorStr<_string_type, _length, _key>& lhs, const _Basic_XorStr<_string_type, _length2, _key2>& rhs)
{
	static_assert(_length == _length2, "XorStr== different length");

	return _length == _length2 && lhs.str() == rhs.str();
}
//---------------------------------------------------------------------------
template<typename _string_type, size_t _length, size_t _key>
inline auto operator==(const _string_type& lhs, const _Basic_XorStr<_string_type, _length, _key>& rhs)
{
	return lhs.size() == _length - 1 && lhs == rhs.str();
}
//---------------------------------------------------------------------------
template<typename _stream_type, typename _string_type, size_t _length, size_t _key>
inline auto& operator<<(_stream_type& lhs, const _Basic_XorStr<_string_type, _length, _key>& rhs)
{
	lhs << rhs.c_str();

	return lhs;
}
//---------------------------------------------------------------------------
template<typename _string_type, size_t _length, size_t _key, size_t _length2, size_t _key2>
inline auto operator+(const _Basic_XorStr<_string_type, _length, _key>& lhs, const _Basic_XorStr<_string_type, _length2, _key2>& rhs)
{
	return lhs.str() + rhs.str();
}
//---------------------------------------------------------------------------
template<typename _string_type, size_t _length, size_t _key>
inline auto operator+(const _string_type& lhs, const _Basic_XorStr<_string_type, _length, _key>& rhs)
{
	return lhs + rhs.str();
}
//---------------------------------------------------------------------------
template<size_t _length, size_t _key = keyauth_xor_build_key(__TIME__)>
constexpr ALWAYS_INLINE auto XorStr(char const (&str)[_length])
{
	return XorStrA<_length, _key>(str);
}
//---------------------------------------------------------------------------
template<size_t _length, size_t _key = keyauth_xor_build_key(__TIME__)>
constexpr ALWAYS_INLINE auto XorStr(wchar_t const (&str)[_length])
{
	return XorStrW<_length, _key>(str);
}
//---------------------------------------------------------------------------
template<size_t _length, size_t _key = keyauth_xor_build_key(__TIME__)>
constexpr ALWAYS_INLINE auto XorStr(char16_t const (&str)[_length])
{
	return XorStrU16<_length, _key>(str);
}
//---------------------------------------------------------------------------
template<size_t _length, size_t _key = keyauth_xor_build_key(__TIME__)>
constexpr ALWAYS_INLINE auto XorStr(char32_t const (&str)[_length])
{
	return XorStrU32<_length, _key>(str);
}
//---------------------------------------------------------------------------