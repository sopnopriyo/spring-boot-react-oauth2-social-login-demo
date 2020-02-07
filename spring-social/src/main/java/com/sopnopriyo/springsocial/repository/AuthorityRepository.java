package com.sopnopriyo.springsocial.repository;

import com.sopnopriyo.springsocial.model.Authority;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthorityRepository extends JpaRepository<Authority, Long> {
    Authority findByName(String type);
}
