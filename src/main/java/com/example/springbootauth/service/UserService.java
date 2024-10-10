package com.example.springbootauth.service;

import com.example.springbootauth.model.User;
import com.example.springbootauth.repo.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> byUsername = userRepo.findByUsername(username);
        if (byUsername.isPresent())
            return byUsername.get();
        throw new UsernameNotFoundException("Invalid user");
    }
}
