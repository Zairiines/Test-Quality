import { Component } from '@angular/core';
import { MatDialogRef } from '@angular/material/dialog';
import { ContractService } from '../services/contract.service';
import { Contract } from '../models/contract.model';

@Component({
  selector: 'app-add-contract-dialog',
  templateUrl: './add-contract-dialog.component.html',
  styleUrls: ['./add-contract-dialog.component.scss']
})
export class AddContractDialogComponent {
  newContract: Contract = {
    dateDebut: '',
    dateFin: '',
    entrepriseName: '',
    userId: 0,
    title: '',          // Ajout du champ title
    description: ''    // Ajout du champ description
  };

  constructor(
    private contractService: ContractService,
    private dialogRef: MatDialogRef<AddContractDialogComponent>
  ) {}

  createContract(): void {
    this.contractService.createContract(this.newContract).subscribe(contract => {
      console.log('Contrat créé : ', contract);
      this.dialogRef.close(contract);  // Ferme le dialogue après la création
    });
  }

  closeDialog(): void {
    this.dialogRef.close();
  }
}
