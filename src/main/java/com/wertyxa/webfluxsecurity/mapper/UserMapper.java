package com.wertyxa.webfluxsecurity.mapper;

import com.wertyxa.webfluxsecurity.dto.UserDto;
import com.wertyxa.webfluxsecurity.entity.UserEntity;
import org.mapstruct.InheritInverseConfiguration;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {
    UserDto map(UserEntity userEntity);
    @InheritInverseConfiguration
    UserEntity map(UserDto dto);
}
