package com.example.JwtTest.repository;

import com.example.JwtTest.entity.User;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface UserRepository extends CrudRepository<User,Long> {
    User findByUsername(String username);
}