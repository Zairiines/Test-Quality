import { ComponentFixture, TestBed } from '@angular/core/testing';

import { UpdateContractDialogComponentComponent } from './update-contract-dialog-component.component';

describe('UpdateContractDialogComponentComponent', () => {
  let component: UpdateContractDialogComponentComponent;
  let fixture: ComponentFixture<UpdateContractDialogComponentComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [UpdateContractDialogComponentComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(UpdateContractDialogComponentComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
