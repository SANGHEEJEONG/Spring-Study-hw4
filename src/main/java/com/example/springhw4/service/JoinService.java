package com.example.springhw4.service;

import com.example.springhw4.dto.JoinDTO;
import com.example.springhw4.entity.UserEntity;
import com.example.springhw4.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public void joinProcess(JoinDTO joinDTO){

        String username = joinDTO.getUsername();
        String password = joinDTO.getPassword();

        Boolean isExist = userRepository.existsByUsername(username);

        if (isExist){

            return;
        }

        UserEntity data = new UserEntity();

        data.setUsername(username);
        data.setPassword(bCryptPasswordEncoder.encode(password)); // 암호화 진행 후 주입
        data.setRole("ROLE_ADMIN"); // 접두사를 무조건 가져야 함

        userRepository.save(data);
    }
}
