package project.practice.domain;

import jakarta.persistence.*;
import lombok.Data;

@Entity
@Data
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long Id;

    @Column
    private String username;

    @Column
    private String password;

    @Column
    private String email;

    @Column
    private String age;

    @Column
    private String role;
}
