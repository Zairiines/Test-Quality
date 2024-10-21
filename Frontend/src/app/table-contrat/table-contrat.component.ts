import { Component, OnInit } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { ContractService } from '../services/contract.service';
import { ContractDTO } from '../models/contract.model';
import { AddContractDialogComponent } from '../add-contract-dialog/add-contract-dialog.component';
import { UpdateContractDialogComponent } from '../update-contract-dialog/update-contract-dialog.component';

@Component({
  selector: 'app-table-contrat',
  templateUrl: './table-contrat.component.html',
  styleUrls: ['./table-contrat.component.scss']
})
export class TableContratComponent implements OnInit {
  contracts: ContractDTO[] = [];
  filteredContracts: ContractDTO[] = [];
  searchName: string = ''; // Variable pour stocker le nom recherché
  displayedColumns: string[] = ['title', 'description', 'entrepriseName', 'dateDebut', 'dateFin', 'documents', 'actions'];
  showConfirmation = false;
  contractIdToDelete: number | null = null;

  constructor(
    private contractService: ContractService,
    private dialog: MatDialog
  ) {}

  ngOnInit(): void {
    this.loadContracts(); // Charger les contrats au démarrage
  }

  loadContracts(): void {
    this.contractService.getAllContracts().subscribe((data: ContractDTO[]) => {
      this.contracts = data;
      this.filteredContracts = this.contracts; // Initialiser filteredContracts
    });
  }

  
  searchContracts(): void {
    console.log('Searching for contract with name:', this.searchName);
    if (this.searchName) {
      this.contractService.getContractByName(this.searchName).subscribe(
        (contract: ContractDTO) => {
          console.log('Contract received:', contract);
          if (contract) {
            this.filteredContracts = [contract];
            console.log('Company Name:', contract.entrepriseName);  // Vérifiez ici si entrepriseName est correct
          } else {
            alert('Contract not found');
            this.filteredContracts = [];
          }
        },
        (error) => {
          console.error('Error fetching contract by name', error);
          alert('Contract not found');
          this.filteredContracts = [];
        }
      );
    } else {
      this.loadContracts(); // Recharge tous les contrats si aucun nom n'est entré
    }
  }
  
  openUpdateContractDialog(contract: ContractDTO): void {
    const dialogRef = this.dialog.open(UpdateContractDialogComponent, {
      width: '400px',
      data: { contract: contract }
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        this.contractService.updateContract(result.contractId!, result).subscribe(() => {
          this.loadContracts(); // Rafraîchit la liste après mise à jour
        });
      }
    });
  }

  deleteContract(contractId: number): void {
    this.showConfirmation = true;
    this.contractIdToDelete = contractId;
  }

  confirmDelete(): void {
    if (this.contractIdToDelete !== null) {
      this.contractService.deleteContract(this.contractIdToDelete).subscribe(() => {
        this.loadContracts(); // Recharger les contrats après suppression
        this.showConfirmation = false;
        this.contractIdToDelete = null;
      });
    }
  }

  cancelDelete(): void {
    this.showConfirmation = false;
    this.contractIdToDelete = null;
  }

  openAddContractDialog(): void {
    const dialogRef = this.dialog.open(AddContractDialogComponent, {
      width: '400px'
    });

    dialogRef.afterClosed().subscribe(result => {
      if (result) {
        this.loadContracts();  // Rafraîchit la liste après l'ajout
      }
    });
  }

  onSort(column: string): void {
    // Logique de tri pour les colonnes
    console.log('Sorting by column:', column);
  }
}
