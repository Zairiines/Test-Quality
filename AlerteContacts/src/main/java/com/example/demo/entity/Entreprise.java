package com.example.demo.entity;

import java.util.Set;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import jakarta.persistence.OneToMany;

@Entity
@Table
@NoArgsConstructor
@RequiredArgsConstructor
public class Entreprise {

    
	@Id
    @SequenceGenerator(
            name = "enterprise_sequence",
            sequenceName = "enterprise_sequence",
            allocationSize = 1
    )
    @GeneratedValue(strategy = GenerationType.SEQUENCE,
                    generator = "enterprise_sequence")
    private Long id;

    @NonNull
    @Column(name = "name", nullable = false)
    private String name;

    @NonNull
    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @NonNull
    @Column(name = "phone", nullable = false)
    private String phone;
   
    
    public Entreprise(@NonNull String name, @NonNull String email, @NonNull String phone) {
		super();
		this.name = name;
		this.email = email;
		this.phone = phone;
	}

	@OneToMany(cascade=CascadeType.ALL, mappedBy="entreprise")
    private Set<Contract> contract;
    private boolean deleted = false;
    
	public boolean isDeleted() {
		return deleted;
	}

	public void setDeleted(boolean deleted) {
		this.deleted = deleted;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPhone() {
		return phone;
	}

	public void setPhone(String phone) {
		this.phone = phone;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	
    
}
