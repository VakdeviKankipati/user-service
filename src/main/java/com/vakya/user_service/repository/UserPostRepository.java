package com.vakya.user_service.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserPostRepository extends JpaRepository<UserPost, Long> {
    List<UserPost> findByUserId(Integer userId);
    List<UserPost> findByPostId(Long postId);
    UserPost findByUserIdAndPostId(Integer userId, Long postId);
} 