package project.practice.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import project.practice.domain.Account;

public interface UserRepository extends JpaRepository<Account, Long> {

    Account findByUsername(String username);
}
