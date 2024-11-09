package com.example.springhw4.repository;

import com.example.springhw4.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<UserEntity,Integer> {


}
