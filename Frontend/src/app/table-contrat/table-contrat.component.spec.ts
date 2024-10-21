import { ComponentFixture, TestBed } from '@angular/core/testing';

import { TableContratComponent } from './table-contrat.component';

describe('TableContratComponent', () => {
  let component: TableContratComponent;
  let fixture: ComponentFixture<TableContratComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [TableContratComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(TableContratComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
