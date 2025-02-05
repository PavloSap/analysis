tasks = {}

loop do
  puts "1. Add Task"
  puts "2. View Tasks"
  puts "3. Delete Task"
  puts "4. Exit"
  print "Choose an option: "
  choice = gets.chomp.to_i

  case choice
  when 1
    print "Enter task: "
    task = gets.chomp
    id = tasks.size + 1
    tasks[id] = task
  when 2
    tasks.each { |id, task| puts "#{id}: #{task}" }
  when 3
    print "Enter task ID to delete: "
    id = gets.chomp.to_i
    tasks.delete(id)
  when 4
    break
  else
    puts "Invalid choice."
  end
end
