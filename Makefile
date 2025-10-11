.PHONY: setup test type-check lint format format-check clean server

setup:
	bundle install

test:
	bundle exec rspec

type-check:
	@echo "Ruby does not require type checking"

lint:
	bundle exec rubocop

format:
	bundle exec rubocop -a

format-check:
	bundle exec rubocop

server:
	bundle exec ruby examples/server.rb

clean:
	rm -rf .bundle vendor
