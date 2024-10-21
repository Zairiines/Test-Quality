import { Component, OnInit } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { EntrepriseService } from 'src/app/services/entreprise.service';
import { UserService } from 'src/app/services/user.service';
import { Entreprise } from 'src/app/models/entreprise.model';
import { User } from 'src/app/models/user.model';
import { AddEntrepriseDialogComponent } from '../add-entreprise-dialog/add-entreprise-dialog.component';
import { UpdateEntrepriseDialogComponent } from '../update-entreprise-dialog/update-entreprise-dialog.component';

@Component({
  selector: 'app-table-entreprise',
  templateUrl: './table-entreprise.component.html',
  styleUrls: ['./table-entreprise.component.scss']
})
export class TableEntrepriseComponent implements OnInit {
  entreprises: Entreprise[] = [];
  isAdmin: boolean = false;
  showConfirmation: boolean = false;
  editingEntrepriseId: number | null = null;
  displayedColumns: string[] = ['name', 'email', 'phone', 'actions'];
  
  searchName: string = ''; // Variable pour stocker le nom recherché

  constructor(
    private entrepriseService: EntrepriseService,
    private userService: UserService,
    private dialog: MatDialog
  ) {}

  ngOnInit(): void {
    this.loadEntreprises();
    this.checkAdminRole();
  }

  loadEntreprises(): void {
    this.entrepriseService.getAllEntreprises().subscribe((data: Entreprise[]) => {
      this.entreprises = data;
    });
  }

  checkAdminRole(): void {
    this.userService.getCurrentUser().subscribe((user: User) => {
      this.isAdmin = user.role === 'ADMIN';
    });
  }

  openAddEntrepriseDialog(): void {
    const dialogRef = this.dialog.open(AddEntrepriseDialogComponent, {
      width: '400px'
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        this.loadEntreprises();
      }
    });
  }

  selectEntrepriseForUpdate(entreprise: Entreprise): void {
    const dialogRef = this.dialog.open(UpdateEntrepriseDialogComponent, {
      width: '400px',
      data: { entreprise }
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        this.entrepriseService.updateEntreprise(entreprise.id, result).subscribe(() => {
          this.loadEntreprises();
        });
      }
    });
  }

  openConfirmation(entrepriseId: number | undefined): void {
    if (entrepriseId !== undefined) {
      this.editingEntrepriseId = Number(entrepriseId);
      this.showConfirmation = true;
    }
  }

  confirmDelete(): void {
    if (this.editingEntrepriseId !== null) {
      this.entrepriseService.deleteEntreprise(this.editingEntrepriseId).subscribe(() => {
        this.loadEntreprises();
        this.editingEntrepriseId = null;
        this.showConfirmation = false;
      });
    }
  }

  cancelDelete(): void {
    this.showConfirmation = false;
    this.editingEntrepriseId = null;
  }

  // Méthode pour rechercher une entreprise par nom
  searchEntrepriseByName(): void {
    if (this.searchName) {
      this.entrepriseService.getEntrepriseByName(this.searchName).subscribe((entreprise: Entreprise) => {
        this.entreprises = [entreprise];
      }, () => {
        alert('Entreprise not found');
      });
    } else {
      this.loadEntreprises(); // Recharge toutes les entreprises si aucun nom n'est entré
    }
  }
}
