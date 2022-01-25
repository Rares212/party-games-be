package com.mps.partygames.repo;

import com.mps.partygames.model.Host;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface HostRepository extends JpaRepository<Host, Long> {
    Optional<Host> findByUsername(String username);

    List<Host> findAllByEnabledTrue();
}