import { Component, Input, ViewEncapsulation } from "@angular/core";

@Component({
  selector: "app-copy-input",
  templateUrl: "./copy-input.component.html",
  styleUrls: ["./copy-input.component.less"],
  encapsulation: ViewEncapsulation.None
})
export class CopyInputComponent {
  @Input() value = "";

  async copy(value) {
    await (navigator as any).clipboard.writeText(value);
  }
}
