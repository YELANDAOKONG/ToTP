import totp3

print(totp3.generate_key(128))
print(totp3.generate_key_plus(128))

print(totp3.generate_totp_now("114514"))
print(totp3.generate_totp_plus_now("114514"))
print(totp3.generate_totp_simple_now("114514"))
print(totp3.generate_totp_simplest_now("114514"))

print(totp3.generate_totp_number_now("114514"))
print(totp3.generate_totp_number_plus_now("114514"))
print(totp3.generate_totp_number_simple_now("114514"))
print(totp3.generate_totp_number_simplest_now("114514"))