abstract class Person {
    protected String name;
    protected int id;

    public Person(String name, int id) {
        this.name = name;
        this.id = id;
    }

    abstract void showRole();
}

class Customer extends Person {
    public Customer(String name, int id) {
        super(name, id);
    }

    public void showRole() {
        System.out.println("Customer Name: " + name + " | ID: " + id);
    }
}

class Product {
    private String itemName;
    private double price;

    public Product(String itemName, double price) {
        this.itemName = itemName;
        this.price = price;
    }

    public String getItemName() {
        return itemName;
    }

    public double getPrice() {
        return price;
    }
}

class Order {
    protected Customer customer;
    protected Product product;
    protected int quantity;

    public Order(Customer customer, Product product, int quantity) {
        this.customer = customer;
        this.product = product;
        this.quantity = quantity;
    }

    public void showOrder() {
        System.out.println(customer.name + " bought " + quantity + " x " + product.getItemName());
        System.out.println("Total Price: " + (quantity * product.getPrice()));
    }
}

class DiscountOrder extends Order {
    public DiscountOrder(Customer customer, Product product, int quantity) {
        super(customer, product, quantity);
    }

    public void showOrder() {
        System.out.println("Discount Applied Order:");
        super.showOrder();
    }
}

public class Main {
    public static void main(String[] args) {

        Customer c1 = new Customer("Shehab", 232);
        Customer c2 = new Customer("Atiya", 119);
        Customer c3 = new Customer("Shafayet", 555);
        Customer c4 = new Customer("Trisha", 167);
        Customer c5 = new Customer("Tanzila", 712);

        Product p1 = new Product("Laptop", 80000);
        Product p2 = new Product("Mouse", 500);
        Product p3 = new Product("Keyboard", 1500);

        Order o1 = new Order(c1, p1, 1);
        Order o2 = new Order(c2, p2, 2);
        Order o3 = new DiscountOrder(c3, p3, 1);
        Order o4 = new Order(c4, p2, 3);
        Order o5 = new DiscountOrder(c5, p1, 1);

        c1.showRole();
        o1.showOrder();

        c2.showRole();
        o2.showOrder();

        c3.showRole();
        o3.showOrder();

        c4.showRole();
        o4.showOrder();

        c5.showRole();
        o5.showOrder();
    }
}